using System.Diagnostics;
using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Cms;
using static OneCrypto.Tests.Support.CmsFixture;

namespace OneCrypto.Tests.Cms;

/// <summary>Cross-checks the CMS we write against the openssl command-line tool, used as a compiled program only. Skipped when it is not installed.</summary>
public class OpenSslInteropTests
{
    private static string? Find(string name)
    {
        foreach (string dir in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            string p = Path.Combine(dir, name);
            if (File.Exists(p))
            {
                return p;
            }
        }

        return null;
    }

    private static (int Code, string Output) Run(string exe, params string[] args)
    {
        var psi = new ProcessStartInfo(exe) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string a in args)
        {
            psi.ArgumentList.Add(a);
        }

        using Process p = Process.Start(psi)!;
        string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        return (p.ExitCode, o);
    }

    private static string Temp(string name)
    {
        string dir = Path.Combine(Environment.GetEnvironmentVariable("TMPDIR") ?? Path.GetTempPath(), "onecrypto-cms");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, name);
    }

    public static IEnumerable<object[]> Cases()
    {
        foreach (bool stamped in new[] { false, true })
        {
            yield return [SigScheme.RsaPkcs1, "SHA256", stamped];
            yield return [SigScheme.RsaPss, "SHA256", stamped];
            yield return [SigScheme.Ecdsa, "SHA384", stamped];
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void OpenSslVerifiesTheCmsWeBuildAndWeAgreeWithIt(SigScheme scheme, string hash, bool stamped)
    {
        string? openssl = Find("openssl");
        if (openssl is null)
        {
            return;
        }

        TestPki pki = TestPki.Shared;
        var key = scheme == SigScheme.Ecdsa ? pki.EcSigner : pki.RsaSigner;
        // Written by the signer itself, not by the test kit.
        var signer = CmsSigner.Create(Credential(key), new HashAlgorithmName(hash), CmsRsaPadding.Pkcs1, cades: true);
        _ = scheme;
        byte[] cms = signer.Build(CryptographicOperations.HashData(signer.Hash, Content), DateTimeOffset.UtcNow, stamped ? new TestTsa().Callback : null, CancellationToken.None);
        // The kit also covers the PSS scheme; the signer's own PSS path is covered in CmsSigningTests.
        byte[] kitCms = KitSign(key, new CmsSpec { Scheme = scheme, Hash = new HashAlgorithmName(hash), Cades = true, Timestamp = stamped });
        Assert.True(VerifyOne(cms).IsValid);
        Assert.True(VerifyOne(kitCms).IsValid);

        string tag = $"{scheme}-{hash}-{stamped}";
        File.WriteAllText(Temp("root.pem"), pki.Root.ExportCertificatePem());
        File.WriteAllBytes(Temp(tag + ".bin"), Content);
        foreach ((string name, byte[] blob) in new[] { ("own", cms), ("kit", kitCms) })
        {
            string cmsPath = Temp($"{tag}-{name}.cms");
            File.WriteAllBytes(cmsPath, blob);
            (int code, string output) = Run(openssl, "cms", "-verify", "-inform", "DER", "-in", cmsPath, "-content", Temp(tag + ".bin"), "-binary", "-CAfile", Temp("root.pem"), "-purpose", "any", "-out", Temp(tag + ".out"));
            Assert.True(code == 0, name + ": " + output);

            File.WriteAllBytes(Temp(tag + ".bad"), [.. Content, 0]);
            (int badCode, _) = Run(openssl, "cms", "-verify", "-inform", "DER", "-in", cmsPath, "-content", Temp(tag + ".bad"), "-binary", "-CAfile", Temp("root.pem"), "-purpose", "any", "-out", Temp(tag + ".out"));
            Assert.NotEqual(0, badCode);
        }

        if (stamped)
        {
            // The token inside the signature is itself a CMS that OpenSSL verifies.
            Assert.True(CmsSignedData.TryParse(cms, out CmsSignedData? sd, out _));
            ReadOnlyMemory<byte> token = sd!.Signers[0].FindUnsigned(Oids.SignatureTimeStampToken)!.Values[0];
            File.WriteAllBytes(Temp(tag + ".tst"), token.ToArray());
            (int tcode, string tout) = Run(openssl, "cms", "-verify", "-inform", "DER", "-in", Temp(tag + ".tst"), "-CAfile", Temp("root.pem"), "-purpose", "any", "-out", Temp(tag + ".tstinfo"));
            Assert.True(tcode == 0, tout);
        }
    }
}
