using System.Diagnostics;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Issuance;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Support;

/// <summary>A root and an intermediate CA built with the library, plus helpers for the openssl runs of the issuer-side tests.</summary>
internal sealed class IssuanceKit
{
    /// <summary>The instant everything is issued at; the openssl runs pass it as the verification time.</summary>
    public static readonly DateTimeOffset T0 = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    private static readonly Lazy<IssuanceKit> Shared = new(() => new IssuanceKit());

    public static IssuanceKit Get() => Shared.Value;

    private IssuanceKit()
    {
        RootKey = RSA.Create(3072);
        var opts = new CertificateAuthorityOptions
        {
            OcspUrls = ["http://ocsp.example.test/"],
            CaIssuersUrls = ["http://pki.example.test/ca.crt"],
            CrlUrls = ["http://pki.example.test/ca.crl"],
        };
        Root = CertificateAuthority.CreateRoot(DistinguishedName.Create((KnownOids.Organization, "OneCrypto Tests"), (KnownOids.CommonName, "Test Root")),
            X509Signer.FromRsa(RootKey, HashAlgorithmName.SHA256), T0.AddDays(-30), TimeSpan.FromDays(3650), opts);
        InterKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Certificate inter = Root.Issue(PublicKeyInfo.FromAsymmetricAlgorithm(InterKey), DistinguishedName.Create((KnownOids.Organization, "OneCrypto Tests"), (KnownOids.CommonName, "Test Intermediate")),
            new CertificateIssueOptions { Profile = CertificateProfile.Intermediate, NotBefore = T0.AddDays(-20), Validity = TimeSpan.FromDays(1800) });
        Intermediate = new CertificateAuthority(inter, X509Signer.FromECDsa(InterKey), opts);
    }

    public RSA RootKey { get; }

    public ECDsa InterKey { get; }

    public CertificateAuthority Root { get; }

    public CertificateAuthority Intermediate { get; }

    public static string Dir(string name)
    {
        string d = Path.Combine(Environment.GetEnvironmentVariable("TMPDIR") ?? Path.GetTempPath(), "onecrypto-issuance", name);
        Directory.CreateDirectory(d);
        return d;
    }

    public static string Write(string dir, string file, string text)
    {
        string p = Path.Combine(dir, file);
        File.WriteAllText(p, text);
        return p;
    }

    public static string Write(string dir, string file, byte[] data)
    {
        string p = Path.Combine(dir, file);
        File.WriteAllBytes(p, data);
        return p;
    }

    public static long Epoch(DateTimeOffset t) => t.ToUnixTimeSeconds();

    public static void Ok((int Code, string Output) r, string what) => Assert.True(r.Code == 0, what + ": " + r.Output);

    /// <summary>Runs the signer program of the two-phase tests in a separate dotnet process.</summary>
    public static byte[] SignInOtherProcess(string dir, string kind, byte[] keyFile, byte[] state)
    {
        string signer = Directory.GetFiles(AppContext.BaseDirectory, "*TwoPhaseSigner.dll").Single();
        string keyPath = Write(dir, "key.bin", keyFile), statePath = Write(dir, "state.der", state), sigPath = Path.Combine(dir, "sig.bin");
        File.Delete(sigPath);
        string? root = Environment.GetEnvironmentVariable("DOTNET_ROOT");
        string dotnet = root is not null && File.Exists(Path.Combine(root, "dotnet")) ? Path.Combine(root, "dotnet") : "dotnet";
        var psi = new ProcessStartInfo(dotnet) { RedirectStandardError = true, RedirectStandardOutput = true };
        foreach (string a in new[] { signer, kind, keyPath, statePath, sigPath })
        {
            psi.ArgumentList.Add(a);
        }

        using Process p = Process.Start(psi)!;
        Task<string> err = p.StandardError.ReadToEndAsync();
        p.WaitForExit();
        Assert.True(p.ExitCode == 0, "signer process failed: " + err.Result);
        return File.ReadAllBytes(sigPath);
    }
}
