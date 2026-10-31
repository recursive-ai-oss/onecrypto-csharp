using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.X509;
using AlgorithmIdentifier = System.Security.Cryptography.Pkcs.AlgorithmIdentifier;
using CmsRecipient = RecursiveAI.OneCrypto.CmsRecipient;
using ContentInfo = System.Security.Cryptography.Pkcs.ContentInfo;
using PublicKeyInfo = RecursiveAI.OneCrypto.PublicKeyInfo;

namespace OneCrypto.Benchmarks;

/// <summary>One signing identity in the forms each library takes it: ours, BouncyCastle's, and the platform's.</summary>
internal sealed class CmsIdentity
{
    private CmsIdentity()
    {
    }

    public Certificate Cert { get; private set; } = null!;

    public X509Signer Signer { get; private set; } = null!;

    public RSA? Rsa { get; private set; }

    public ECDiffieHellman? Ecdh { get; private set; }

    public X509Certificate2 Platform { get; private set; } = null!;

    public Org.BouncyCastle.X509.X509Certificate BcCert { get; private set; } = null!;

    public AsymmetricKeyParameter BcPrivate { get; private set; } = null!;

    public static CmsIdentity Create(string kind, bool agreement = false)
    {
        var id = new CmsIdentity();
        DateTimeOffset now = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
        byte[] pkcs8;
        PublicKeyInfo pub;
        ECDsa? ecdsa = null;
        if (kind == "rsa2048")
        {
            id.Rsa = RSA.Create(2048);
            pkcs8 = id.Rsa.ExportPkcs8PrivateKey();
            id.Signer = X509Signer.FromRsa(id.Rsa, HashAlgorithmName.SHA256);
            pub = id.Signer.PublicKey;
        }
        else
        {
            ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            id.Signer = X509Signer.FromECDsa(ecdsa);
            if (agreement)
            {
                id.Ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                pkcs8 = id.Ecdh.ExportPkcs8PrivateKey();
                pub = PublicKeyInfo.Parse(id.Ecdh.ExportSubjectPublicKeyInfo());
            }
            else
            {
                pkcs8 = ecdsa.ExportPkcs8PrivateKey();
                pub = id.Signer.PublicKey;
            }
        }

        id.Cert = agreement
            ? CertificateBuilder.Create(
                new CertificateOptions { Subject = DistinguishedName.Create((KnownOids.CommonName, "Bench Recipient")), PublicKey = pub, NotBefore = now, NotAfter = now.AddYears(5) },
                CertificateBuilder.CreateSelfSigned(new CertificateOptions { Subject = DistinguishedName.Create((KnownOids.CommonName, "Bench Issuer")), NotBefore = now, NotAfter = now.AddYears(5) }, id.Signer),
                id.Signer)
            : CertificateBuilder.CreateSelfSigned(
                new CertificateOptions { Subject = DistinguishedName.Create((KnownOids.CommonName, "Bench " + kind)), NotBefore = now, NotAfter = now.AddYears(5) }, id.Signer);
        id.BcCert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(id.Cert.Encoded.ToArray());
        id.BcPrivate = PrivateKeyFactory.CreateKey(pkcs8);
        X509Certificate2 pubCert = X509CertificateLoader.LoadCertificate(id.Cert.Encoded.Span);
        id.Platform = id.Rsa is not null ? pubCert.CopyWithPrivateKey(id.Rsa) : agreement ? pubCert : pubCert.CopyWithPrivateKey(ecdsa!);
        return id;
    }
}

/// <summary>
/// CMS signing: SignedData with signed attributes over 1 KiB and 1 MiB, attached, with the signer's certificate. Against BouncyCastle
/// (managed gate) and <c>SignedCms</c> (reported: it calls the platform's crypto).
/// </summary>
[BenchmarkCategory("cms-sign")]
public class CmsSignRows
{
    private CmsIdentity _id = null!;
    private byte[] _data = [];
    private CmsSignerSpec _spec = null!;

    /// <summary>Key type.</summary>
    [Params("rsa2048", "ec-p256")]
    public string Kind { get; set; } = "ec-p256";

    /// <summary>Content size in bytes.</summary>
    [Params(1024, 1 << 20)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _id = CmsIdentity.Create(Kind);
        _data = RandomNumberGenerator.GetBytes(Size);
        _spec = new CmsSignerSpec { Certificate = _id.Cert, Signer = _id.Signer };
    }

    [Benchmark]
    public int Ours() => SignedData.Create(_data, [_spec]).Encoded.Length;

    [Benchmark]
    public int BouncyCastle()
    {
        var gen = new CmsSignedDataGenerator();
        gen.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder().Build(new Asn1SignatureFactory(Kind == "rsa2048" ? "SHA256WITHRSA" : "SHA256WITHECDSA", _id.BcPrivate), _id.BcCert));
        gen.AddCertificates(CollectionUtilities.CreateStore(new[] { _id.BcCert }));
        return gen.Generate(new CmsProcessableByteArray(_data), true).GetEncoded().Length;
    }

    [Benchmark]
    [BenchmarkCategory("native")]
    public int SignedCmsClass()
    {
        var cms = new SignedCms(new ContentInfo(_data));
        cms.ComputeSignature(new CmsSigner(_id.Platform) { IncludeOption = X509IncludeOption.EndCertOnly });
        return cms.Encode().Length;
    }
}

/// <summary>CMS verification of the message the signing rows make: parse, check the digest and the signature (no chain).</summary>
[BenchmarkCategory("cms-verify")]
public class CmsVerifyRows
{
    private CmsIdentity _id = null!;
    private byte[] _msg = [];

    /// <summary>Key type.</summary>
    [Params("rsa2048", "ec-p256")]
    public string Kind { get; set; } = "ec-p256";

    /// <summary>Content size in bytes.</summary>
    [Params(1024, 1 << 20)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _id = CmsIdentity.Create(Kind);
        _msg = SignedData.Create(RandomNumberGenerator.GetBytes(Size), [new CmsSignerSpec { Certificate = _id.Cert, Signer = _id.Signer }]).Encoded.ToArray();
    }

    [Benchmark]
    public bool Ours() => SignedData.Parse(_msg).Verify().IsValid;

    [Benchmark]
    public bool BouncyCastle()
    {
        var sd = new CmsSignedData(_msg);
        bool ok = true;
        foreach (SignerInformation s in sd.GetSignerInfos().GetSigners())
        {
            ok &= s.Verify(_id.BcCert);
        }

        return ok;
    }

    [Benchmark]
    [BenchmarkCategory("native")]
    public bool SignedCmsClass()
    {
        var cms = new SignedCms();
        cms.Decode(_msg);
        cms.CheckSignature(verifySignatureOnly: true);
        return true;
    }
}

/// <summary>
/// EnvelopedData with RSA key transport and AES-256-CBC content over 1 KiB. Ours and <c>EnvelopedCms</c> use RSA-OAEP with SHA-256;
/// BouncyCastle's generator is called with its default RSA PKCS #1 v1.5 key transport (the one-line call), so its row is the same size of
/// RSA work but a different padding.
/// </summary>
[BenchmarkCategory("cms-envelope")]
public class CmsEnvelopeRows
{
    private CmsIdentity _id = null!;
    private byte[] _data = [];
    private byte[] _oursMsg = [];
    private byte[] _bcMsg = [];
    private byte[] _sysMsg = [];

    /// <summary>Content size in bytes.</summary>
    [Params(1024)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _id = CmsIdentity.Create("rsa2048");
        _data = RandomNumberGenerator.GetBytes(Size);
        _oursMsg = Encrypt();
        _bcMsg = BcEncrypt();
        _sysMsg = SysEncrypt();
    }

    private byte[] Encrypt() => EnvelopedData.Create(_data, [CmsRecipient.KeyTransport(_id.Cert, KeyTransportScheme.OaepSha256)]).Encoded.ToArray();

    private byte[] BcEncrypt()
    {
        var gen = new CmsEnvelopedDataGenerator();
        gen.AddKeyTransRecipient(_id.BcCert);
        return gen.Generate(new CmsProcessableByteArray(_data), new Org.BouncyCastle.Asn1.DerObjectIdentifier(CmsEnvelopedGenerator.Aes256Cbc)).GetEncoded();
    }

    private byte[] SysEncrypt()
    {
        var env = new EnvelopedCms(new ContentInfo(_data), new AlgorithmIdentifier(new Oid("2.16.840.1.101.3.4.1.42")));
        env.Encrypt(new System.Security.Cryptography.Pkcs.CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, _id.Platform, RSAEncryptionPadding.OaepSHA256));
        return env.Encode();
    }

    [Benchmark]
    public int Ours() => Encrypt().Length;

    [Benchmark]
    public int BouncyCastle() => BcEncrypt().Length;

    [Benchmark]
    [BenchmarkCategory("native")]
    public int EnvelopedCmsClass() => SysEncrypt().Length;

    /// <summary>Decrypt, the matching direction.</summary>
    [Benchmark]
    [BenchmarkCategory("decrypt")]
    public int OursDecrypt()
    {
        using CmsDecryptionKey k = CmsDecryptionKey.FromRsa(_id.Rsa!, _id.Cert);
        return EnvelopedData.Parse(_oursMsg).Decrypt(k).Length;
    }

    /// <summary>Decrypt with BouncyCastle.</summary>
    [Benchmark]
    [BenchmarkCategory("decrypt")]
    public int BouncyCastleDecrypt()
    {
        var ed = new CmsEnvelopedData(_bcMsg);
        foreach (RecipientInformation r in ed.GetRecipientInfos().GetRecipients())
        {
            return r.GetContent(_id.BcPrivate).Length;
        }

        return 0;
    }

    /// <summary>Decrypt with the platform's EnvelopedCms.</summary>
    [Benchmark]
    [BenchmarkCategory("decrypt", "native")]
    public int EnvelopedCmsDecrypt()
    {
        var env = new EnvelopedCms();
        env.Decode(_sysMsg);
        env.Decrypt(new X509Certificate2Collection(_id.Platform));
        return env.ContentInfo.Content.Length;
    }
}

/// <summary>EnvelopedData to an ECDH P-256 recipient (ephemeral-static, X9.63 KDF, AES-256 key wrap): ours only, as the comparators have no one-call equivalent.</summary>
[BenchmarkCategory("cms-envelope-ecdh")]
public class CmsEcdhRows
{
    private CmsIdentity _id = null!;
    private byte[] _data = [];
    private byte[] _msg = [];

    [GlobalSetup]
    public void Setup()
    {
        _id = CmsIdentity.Create("ec-p256", agreement: true);
        _data = RandomNumberGenerator.GetBytes(1024);
        _msg = EnvelopedData.Create(_data, [CmsRecipient.KeyAgreement(_id.Cert)]).Encoded.ToArray();
    }

    [Benchmark]
    public int OursEncrypt() => EnvelopedData.Create(_data, [CmsRecipient.KeyAgreement(_id.Cert)]).Encoded.Length;

    [Benchmark]
    public int OursDecrypt()
    {
        using CmsDecryptionKey k = CmsDecryptionKey.FromECDiffieHellman(_id.Ecdh!, _id.Cert);
        return EnvelopedData.Parse(_msg).Decrypt(k).Length;
    }
}
