using System.Diagnostics;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Keys.Pkcs11;
using RecursiveAI.OneCrypto.OpenPgp;

namespace OneCrypto.Keys.Tests;

/// <summary>
/// Two-phase signing across three processes with the key on the token: one process prepares (it has the document and the public key), a second
/// signs against the token (it has the PIN and the state, never the document), a third completes and checks the signature.
/// </summary>
public class Pkcs11TwoPhaseTests
{
    private static readonly byte[] Data = RandomNumberGenerator.GetBytes(200_000);

    private static string Work(string name)
    {
        string d = Path.Combine(SoftHsm.Work, "twophase", name);
        Directory.CreateDirectory(d);
        return d;
    }

    /// <summary>Runs one step of the helper program in its own dotnet process and returns its exit code and error output.</summary>
    private static (int Code, string Error) Step(params string[] args)
    {
        string program = Directory.GetFiles(AppContext.BaseDirectory, "*Pkcs11TwoPhase.dll").Single();
        string? root = Environment.GetEnvironmentVariable("DOTNET_ROOT");
        string dotnet = root is not null && File.Exists(Path.Combine(root, "dotnet")) ? Path.Combine(root, "dotnet") : "dotnet";
        var psi = new ProcessStartInfo(dotnet) { RedirectStandardError = true, RedirectStandardOutput = true };
        psi.ArgumentList.Add(program);
        foreach (string a in args)
        {
            psi.ArgumentList.Add(a);
        }

        psi.Environment["PKCS11_PIN"] = SoftHsm.UserPin;
        using Process p = Process.Start(psi)!;
        Task<string> err = p.StandardError.ReadToEndAsync();
        p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        return (p.ExitCode, err.Result);
    }

    private static void Ok((int Code, string Error) r, string what) => Assert.True(r.Code == 0, what + ": " + r.Error);

    [Theory]
    [InlineData("rsa-pkcs1")]
    [InlineData("rsa-pss")]
    [InlineData("ecdsa")]
    [InlineData("ed25519")]
    public void CmsIsPreparedSignedByTheTokenInAnotherProcessAndCompletedInAThird(string kind)
    {
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open();
        using (module)
        using (session)
        {
            (string label, byte[] id) = SoftHsm.Fresh("2p-" + kind);
            Pkcs11KeyPairSpec ks = kind switch
            {
                "ecdsa" => Pkcs11KeyPairSpec.P256(),
                "ed25519" => Pkcs11KeyPairSpec.Ed25519(),
                _ => Pkcs11KeyPairSpec.Rsa(2048),
            };
            Assert.SkipUnless(kind != "ed25519" || session.Slot.GetMechanisms().Contains(0x1055), "the token has no EdDSA");
            Pkcs11Key key = session.GenerateKeyPair(ks, label, id);
            SignatureSpec spec = kind switch
            {
                "rsa-pkcs1" => SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256),
                "rsa-pss" => SignatureSpec.RsaPss(HashAlgorithmName.SHA256),
                "ecdsa" => SignatureSpec.Ecdsa(HashAlgorithmName.SHA256),
                _ => SignatureSpec.Ed25519(),
            };
            var cert = TokenCertificates.SelfSigned("two-phase " + kind, (ISigningKey)key, RecursiveAI.OneCrypto.X509.KeyUsages.DigitalSignature, spec);
            string dir = Work("cms-" + kind);
            string certFile = Path.Combine(dir, "cert.der"), dataFile = Path.Combine(dir, "data.bin"), state = Path.Combine(dir, "cms.state"), sigState = Path.Combine(dir, "sig.state"), raw = Path.Combine(dir, "raw.sig"), output = Path.Combine(dir, "out.der");
            File.WriteAllBytes(certFile, cert.Encoded.ToArray());
            File.WriteAllBytes(dataFile, Data);

            Ok(Step("prepare-cms", certFile, kind, dataFile, state, sigState), "prepare");
            Ok(Step("sign", SoftHsm.Module!, SoftHsm.MainToken, label, sigState, raw), "sign against the token");
            Assert.True(new FileInfo(raw).Length > 0);

            // A signature that is not the token's does not complete.
            byte[] flipped = File.ReadAllBytes(raw);
            flipped[flipped.Length / 2] ^= 1;
            File.WriteAllBytes(raw + ".bad", flipped);
            Assert.NotEqual(0, Step("complete-cms", state, raw + ".bad", output).Code);
            Assert.False(File.Exists(output));

            Ok(Step("complete-cms", state, raw, output), "complete");
            SignedData sd = SignedData.Parse(File.ReadAllBytes(output));
            Assert.True(sd.Verify(Data).IsValid);
            Assert.False(sd.Verify("other"u8).IsValid);

            if (TokenTools.OpenSsl is not null && (kind != "ed25519" || TokenTools.OpenSslAtLeast(3, 5)))
            {
                var r = TokenTools.Run(TokenTools.OpenSsl, null, "cms", "-verify", "-inform", "DER", "-in", output, "-content", dataFile, "-noverify", "-binary", "-out", Path.Combine(dir, "o.bin"));
                Assert.True(r.Code == 0, "openssl cms -verify: " + r.Error);
            }
        }
    }

    [Theory]
    [InlineData(PgpKeyProfile.Rfc4880Rsa)]
    [InlineData(PgpKeyProfile.NistP256)]
    [InlineData(PgpKeyProfile.Rfc9580)]
    public void OpenPgpIsPreparedSignedByTheTokenInAnotherProcessAndCompletedInAThird(PgpKeyProfile profile)
    {
        Pkcs11PgpTests.Imported imp = Pkcs11PgpTests.Import(profile, out string run);
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open("u-import");
        using (module)
        using (session)
        {
            Pkcs11Key token = Pkcs11PgpTests.Open(session, imp, run, 0);
            string dir = Work("pgp-" + profile);
            string certFile = Path.Combine(dir, "cert.pgp"), dataFile = Path.Combine(dir, "data.bin"), state = Path.Combine(dir, "pgp.state"), raw = Path.Combine(dir, "raw.sig"), output = Path.Combine(dir, "out.asc"), spki = Path.Combine(dir, "key.spki");
            File.WriteAllBytes(certFile, imp.Public.ExportPublic());
            File.WriteAllBytes(dataFile, Data);
            File.WriteAllBytes(spki, token.PublicKey.Encoded.ToArray());

            Ok(Step("prepare-pgp", certFile, dataFile, state), "prepare");
            Ok(Step("sign", SoftHsm.Module!, "u-import", token.Label, state, raw, spki), "sign against the token");
            Ok(Step("complete-pgp", state, raw, output), "complete");

            var result = PgpMessageReader.VerifyDetached(new MemoryStream(Data), File.OpenRead(output), new PgpReadOptions { Now = new DateTimeOffset(2026, 6, 1, 12, 5, 0, TimeSpan.Zero), Certificates = [imp.Public] });
            Assert.Contains(result.Signatures, s => s.IsValid);
            Assert.False(File.Exists(output + ".x"));

            byte[] flipped = File.ReadAllBytes(raw);
            flipped[^1] ^= 1;
            File.WriteAllBytes(raw + ".bad", flipped);
            Assert.NotEqual(0, Step("complete-pgp", state, raw + ".bad", output + ".bad").Code);

            if (TokenTools.Sqop is not null)
            {
                var r = TokenTools.Run(TokenTools.Sqop, dataFile, "verify", output, certFile);
                Assert.True(r.Code == 0, "sqop verify: " + r.Error);
            }
        }
    }
}
