using System.Diagnostics;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Tests.Primitives;

/// <summary>
/// Two-way checks of Ed25519, Ed448, X25519 and X448 against the openssl command-line program, used as a compiled program only.
/// ONECRYPTO_OPENSSL names the binary (default: openssl on PATH) and ONECRYPTO_OPENSSL_LIB an optional library directory for it.
/// Skipped when no openssl runs.
/// </summary>
public class OpenSslCurveInteropTests
{
    private static readonly string Dir = Path.Combine(Environment.GetEnvironmentVariable("TMPDIR") ?? Path.GetTempPath(), "onecrypto-curves");

    private static (int Code, byte[] Stdout, string Stderr) Run(params string[] args)
    {
        var psi = new ProcessStartInfo(Environment.GetEnvironmentVariable("ONECRYPTO_OPENSSL") ?? "openssl")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        string? lib = Environment.GetEnvironmentVariable("ONECRYPTO_OPENSSL_LIB");
        if (lib is not null)
        {
            psi.Environment["LD_LIBRARY_PATH"] = lib;
            psi.Environment["DYLD_LIBRARY_PATH"] = lib;
        }
        foreach (string a in args)
        {
            psi.ArgumentList.Add(a);
        }
        using Process p = Process.Start(psi)!;
        using var ms = new MemoryStream();
        Task<string> err = p.StandardError.ReadToEndAsync();
        p.StandardOutput.BaseStream.CopyTo(ms);
        p.WaitForExit();
        return (p.ExitCode, ms.ToArray(), err.Result);
    }

    private static bool Available()
    {
        try
        {
            return Run("version").Code == 0;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    private static string InDir(string name)
    {
        Directory.CreateDirectory(Dir);
        return Path.Combine(Dir, name);
    }

    // PKCS#8 and SubjectPublicKeyInfo framing for the raw keys (RFC 8410), written out so that nothing but openssl parses them.
    private static byte[] Pkcs8(string alg, byte[] raw) => Convert.FromHexString(alg switch
    {
        "ed25519" => "302e020100300506032b657004220420",
        "ed448" => "3047020100300506032b6571043b0439",
        "x25519" => "302e020100300506032b656e04220420",
        "x448" => "3046020100300506032b656f043a0438",
        _ => throw new ArgumentException(alg),
    }).Concat(raw).ToArray();

    private static byte[] Spki(string alg, byte[] raw) => Convert.FromHexString(alg switch
    {
        "ed25519" => "302a300506032b6570032100",
        "ed448" => "3043300506032b6571033a00",
        "x25519" => "302a300506032b656e032100",
        "x448" => "3042300506032b656f033900",
        _ => throw new ArgumentException(alg),
    }).Concat(raw).ToArray();

    private static void WritePem(string path, string label, byte[] der) =>
        File.WriteAllText(path, $"-----BEGIN {label}-----\n{Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks)}\n-----END {label}-----\n");

    private static int RawLength(string alg) => alg switch { "ed25519" => 32, "ed448" => 57, "x25519" => 32, _ => 56 };

    /// <summary>Generates a key with openssl and returns its raw private and public bytes.</summary>
    private static (byte[] Priv, byte[] Pub) OpenSslKey(string alg, string name)
    {
        string pem = InDir(name + ".pem");
        Assert.Equal(0, Run("genpkey", "-algorithm", alg, "-out", pem).Code);
        byte[] priv = Run("pkey", "-in", pem, "-outform", "DER").Stdout;
        byte[] pub = Run("pkey", "-in", pem, "-pubout", "-outform", "DER").Stdout;
        int n = RawLength(alg);
        return (priv[^n..], pub[^n..]);
    }

    [Theory]
    [InlineData("ed25519")]
    [InlineData("ed448")]
    public void EdDsaSignaturesVerifyBothWays(string alg)
    {
        Assert.SkipUnless(Available(), "openssl is not installed");
        string msgPath = InDir("msg.bin");
        for (int i = 0; i < 6; i++)
        {
            byte[] msg = new byte[(i * 37) + 1]; // openssl pkeyutl -rawin refuses an empty file
            Random.Shared.NextBytes(msg);
            File.WriteAllBytes(msgPath, msg);

            // openssl key, openssl signature -> we verify; our signature must be byte-identical (EdDSA is deterministic).
            (byte[] priv, byte[] pub) = OpenSslKey(alg, "k" + alg);
            string pemPriv = InDir("k" + alg + ".pem");
            string sigPath = InDir("sig.bin");
            Assert.Equal(0, Run("pkeyutl", "-sign", "-rawin", "-inkey", pemPriv, "-in", msgPath, "-out", sigPath).Code);
            byte[] theirs = File.ReadAllBytes(sigPath);
            byte[] derived = new byte[pub.Length];
            byte[] ours = new byte[theirs.Length];
            if (alg == "ed25519")
            {
                Ed25519.DerivePublicKey(priv, derived);
                Assert.True(Ed25519.Verify(pub, msg, theirs));
                Assert.True(Ed25519.TrySign(priv, msg, ours, out _));
            }
            else
            {
                Ed448.DerivePublicKey(priv, derived);
                Assert.True(Ed448.Verify(pub, msg, [], theirs));
                Assert.True(Ed448.TrySign(priv, msg, [], ours, out _));
            }
            Assert.Equal(Convert.ToHexString(pub), Convert.ToHexString(derived));
            Assert.Equal(Convert.ToHexString(theirs), Convert.ToHexString(ours));

            // our key, our signature -> openssl verifies, and rejects a tampered message.
            byte[] seed = new byte[RawLength(alg)];
            System.Security.Cryptography.RandomNumberGenerator.Fill(seed);
            byte[] myPub = new byte[seed.Length];
            byte[] mySig = new byte[theirs.Length];
            if (alg == "ed25519")
            {
                Ed25519.DerivePublicKey(seed, myPub);
                Assert.True(Ed25519.TrySign(seed, msg, mySig, out _));
            }
            else
            {
                Ed448.DerivePublicKey(seed, myPub);
                Assert.True(Ed448.TrySign(seed, msg, [], mySig, out _));
            }
            WritePem(InDir("mypub.pem"), "PUBLIC KEY", Spki(alg, myPub));
            File.WriteAllBytes(sigPath, mySig);
            Assert.Equal(0, Run("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", InDir("mypub.pem"), "-in", msgPath, "-sigfile", sigPath).Code);
            File.WriteAllBytes(msgPath, [.. msg, 1]);
            Assert.NotEqual(0, Run("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", InDir("mypub.pem"), "-in", msgPath, "-sigfile", sigPath).Code);

            // the same seed as a PKCS#8 file is accepted by openssl and gives the same public key.
            WritePem(InDir("myseed.pem"), "PRIVATE KEY", Pkcs8(alg, seed));
            byte[] viaOpenSsl = Run("pkey", "-in", InDir("myseed.pem"), "-pubout", "-outform", "DER").Stdout;
            Assert.Equal(Convert.ToHexString(myPub), Convert.ToHexString(viaOpenSsl[^myPub.Length..]));
        }
    }

    [Theory]
    [InlineData("x25519")]
    [InlineData("x448")]
    public void SharedSecretsAgreeBothWays(string alg)
    {
        Assert.SkipUnless(Available(), "openssl is not installed");
        for (int i = 0; i < 6; i++)
        {
            (byte[] aPriv, byte[] aPub) = OpenSslKey(alg, "a" + alg);
            (_, byte[] bPub) = OpenSslKey(alg, "b" + alg);
            WritePem(InDir("bpub.pem"), "PUBLIC KEY", Spki(alg, bPub));
            byte[] theirs = Run("pkeyutl", "-derive", "-inkey", InDir("a" + alg + ".pem"), "-peerkey", InDir("bpub.pem")).Stdout;

            byte[] derivedPub = new byte[aPub.Length];
            byte[] ours = new byte[aPub.Length];
            bool ok;
            if (alg == "x25519")
            {
                X25519.DerivePublicKey(aPriv, derivedPub);
                ok = X25519.TryDeriveSharedSecret(aPriv, bPub, ours);
            }
            else
            {
                X448.DerivePublicKey(aPriv, derivedPub);
                ok = X448.TryDeriveSharedSecret(aPriv, bPub, ours);
            }
            Assert.True(ok);
            Assert.Equal(Convert.ToHexString(aPub), Convert.ToHexString(derivedPub));
            Assert.Equal(Convert.ToHexString(theirs), Convert.ToHexString(ours));
        }
    }
}
