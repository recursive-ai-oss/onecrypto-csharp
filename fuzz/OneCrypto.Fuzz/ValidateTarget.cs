using System.Linq;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Fuzz;

/// <summary>
/// The path validator over pools and anchors made of (mutated) certificates and CRLs. The input is a list of blobs, each with a two-octet length:
/// the first is the target, and the first octet of every later blob says whether the rest is a trust anchor, an intermediate or a CRL.
/// Nothing may be thrown; a valid verdict must name a path that ends at the target.
/// </summary>
internal static class ValidateTarget
{
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);

    public static void Run(ReadOnlySpan<byte> data)
    {
        var blobs = new List<byte[]>();
        int pos = 0;
        while (pos + 2 <= data.Length && blobs.Count < 12)
        {
            int len = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            len = Math.Min(len, data.Length - pos);
            blobs.Add(data.Slice(pos, len).ToArray());
            pos += len;
        }

        if (blobs.Count == 0 || !Certificate.TryParse(blobs[0], out Certificate? target) || target is null)
        {
            return;
        }

        var anchors = new List<TrustAnchor>();
        var pool = new List<Certificate>();
        var crls = new List<CertificateRevocationList>();
        foreach (byte[] blob in blobs.Skip(1))
        {
            if (blob.Length < 2)
            {
                continue;
            }

            byte[] body = blob[1..];
            if (blob[0] % 3 == 2 && CertificateRevocationList.TryParse(body, out CertificateRevocationList? crl) && crl is not null)
            {
                crls.Add(crl);
            }
            else if (Certificate.TryParse(body, out Certificate? c) && c is not null)
            {
                if (blob[0] % 3 == 0)
                {
                    anchors.Add(TrustAnchor.FromCertificate(c));
                }
                else
                {
                    pool.Add(c);
                }
            }
        }

        var limits = new ValidationLimits { MaxSearchSteps = 500, MaxSignatureChecks = 64, MaxPathsValidated = 8, MaxPolicyNodes = 500 };
        ValidationReport r = PathValidator.Validate(target, new ValidationOptions
        {
            TrustAnchors = anchors,
            Intermediates = pool,
            ReferenceTime = Now,
            Revocation = crls.Count > 0 ? new RevocationData { Crls = crls } : null,
            RevocationRequired = crls.Count > 0 ? RevocationScope.AllCertificates : RevocationScope.None,
            Limits = limits,
            Policy = RecursiveAI.OneCrypto.Policy.CryptoPolicy.Permissive,
            WebPki = data.Length % 2 == 0 ? new WebPkiProfile { ServerName = "seed.example.test" } : null,
        });
        if (r.Verdict == ValidationVerdict.Valid && (r.SelectedPath is null || !r.SelectedPath.Target.Equals(target)))
        {
            throw new InvalidOperationException("a valid verdict does not end at the target");
        }

        _ = r.ToString();
        _ = r.DecidingRule;
    }

    private static byte[] Blob(byte kind, byte[] body) => [(byte)((body.Length + 1) >> 8), (byte)(body.Length + 1), kind, .. body];

    public static IEnumerable<byte[]> Seeds()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Signer signer = X509Signer.FromECDsa(ec);
        var name = DistinguishedName.Create((KnownOids.CommonName, "seed.example.test"));
        Certificate root = CertificateBuilder.CreateSelfSigned(
            new CertificateOptions
            {
                Subject = DistinguishedName.Create((KnownOids.CommonName, "Seed Root")),
                NotBefore = Now.AddYears(-1),
                NotAfter = Now.AddYears(5),
                Extensions = [Extension.Create(new BasicConstraints(true), true), Extension.Create(new NameConstraints([new GeneralSubtree(GeneralName.Dns("example.test"))], null), true)],
            },
            signer);
        Certificate leaf = CertificateBuilder.Create(
            new CertificateOptions
            {
                Subject = name,
                PublicKey = signer.PublicKey,
                NotBefore = Now.AddYears(-1),
                NotAfter = Now.AddYears(1),
                Extensions = [Extension.Create(new SubjectAlternativeName([GeneralName.Dns("seed.example.test")]), false), Extension.Create(new CertificatePolicies([new PolicyInformation("1.2.3.4", [])]), false)],
            },
            root,
            signer);
        CertificateRevocationList crl = RevocationListBuilder.Create(new RevocationListOptions { ThisUpdate = Now.AddDays(-1), NextUpdate = Now.AddDays(6), Number = 1 }, signer, root);
        byte[] leafBytes = leaf.Encoded.ToArray();
        yield return [(byte)(leafBytes.Length >> 8), (byte)leafBytes.Length, .. leafBytes, .. Blob(0, root.Encoded.ToArray())];
        yield return [(byte)(leafBytes.Length >> 8), (byte)leafBytes.Length, .. leafBytes, .. Blob(0, root.Encoded.ToArray()), .. Blob(2, crl.Encoded.ToArray())];
        yield return [(byte)(leafBytes.Length >> 8), (byte)leafBytes.Length, .. leafBytes, .. Blob(1, root.Encoded.ToArray()), .. Blob(1, leafBytes)];
    }
}
