using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.X509;

public class EdTryTests
{
    [Theory]
    [InlineData("ed25519")]
    [InlineData("ed448")]
    public void OpenSslEdCertificatesVerifyAndOursVerifyInOpenSsl(string alg)
    {
        OpenSslTool.RequireOrSkip();
        string dir = OpenSslTool.TempDir("edtry");
        Assert.Equal(0, OpenSslTool.Run("genpkey", "-algorithm", alg, "-out", Path.Combine(dir, alg + ".key")).Code);
        Assert.Equal(0, OpenSslTool.Run("req", "-x509", "-new", "-key", Path.Combine(dir, alg + ".key"), "-subj", "/CN=ed", "-days", "30", "-out", Path.Combine(dir, alg + ".pem")).Code);
        Certificate theirs = Certificate.FromPem(File.ReadAllText(Path.Combine(dir, alg + ".pem")));
        Assert.True(theirs.IsSelfSigned, theirs.VerifySignature(theirs.PublicKey).Reason);
        byte[] bad = theirs.Encoded.ToArray();
        bad[^3] ^= 1;
        Assert.Equal(SignatureStatus.Invalid, Certificate.Parse(bad).VerifySignature(theirs.PublicKey).Status);

        // Ours: a seed, a delegate signer, a certificate openssl verifies.
        bool is25519 = alg == "ed25519";
        byte[] seed = RandomNumberGenerator.GetBytes(is25519 ? 32 : 57);
        byte[] pub = new byte[is25519 ? 32 : 57];
        if (is25519) { Ed25519.DerivePublicKey(seed, pub); } else { Ed448.DerivePublicKey(seed, pub); }
        string oid = is25519 ? KnownOids.Ed25519 : KnownOids.Ed448;
        PublicKeyInfo key = PublicKeyInfo.Parse(RecursiveAI.OneCrypto.Asn1.DerWriter.Sequence(RecursiveAI.OneCrypto.Asn1.DerWriter.Sequence(RecursiveAI.OneCrypto.Asn1.DerWriter.Oid(oid)), X509Signer_BitString(pub)));
        X509Signer signer = X509Signer.FromDelegate(AlgorithmIdentifier.Create(oid), key, m =>
        {
            byte[] sig = new byte[is25519 ? 64 : 114];
            if (is25519) { Ed25519.TrySign(seed, m, sig, out _); } else { Ed448.TrySign(seed, m, default, sig, out _); }
            return sig;
        });
        Certificate root = CertificateBuilder.CreateSelfSigned(new CertificateOptions { Subject = DistinguishedName.Create((KnownOids.CommonName, "Ed Root")), NotBefore = Pki.Now.AddDays(-1), NotAfter = Pki.Now.AddYears(1), Extensions = [Extension.Create(new BasicConstraints(true), true)] }, signer);
        Assert.True(root.IsSelfSigned);
        File.WriteAllText(Path.Combine(dir, "ours-" + alg + ".pem"), root.ToPem());
        (int code, string text) = OpenSslTool.Run("verify", "-attime", Pki.Now.ToUnixTimeSeconds().ToString(), "-CAfile", Path.Combine(dir, "ours-" + alg + ".pem"), Path.Combine(dir, "ours-" + alg + ".pem"));
        Assert.True(code == 0, text);
    }

    private static byte[] X509Signer_BitString(byte[] b) => [0x03, (byte)(b.Length + 1), 0, .. b];
}
