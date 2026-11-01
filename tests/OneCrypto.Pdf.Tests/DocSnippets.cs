using System.Security.Cryptography;
using OnePdf;
using RecursiveAI.OneCrypto.X509;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.Validation;

namespace RecursiveAI.OneCrypto.Pdf.Tests;

/// <summary>
/// The recipe snippets of docs/pdf.md, docs/online.md, docs/keys.md and docs/cms.md, compiled verbatim (they are not run here; the calls
/// they make are exercised by <see cref="ConsumerApiTests"/>). A snippet that stops compiling breaks the build.
/// </summary>
internal static class DocSnippets
{
    internal static void SignAndArchive(byte[] bytes, Stream output, ISigningKey key, Certificate certificate, IReadOnlyList<Certificate> chain, IReadOnlyList<TrustAnchor> anchors, IReadOnlyList<Certificate> intermediates, DateTimeOffset now, IRevocationSource revocationSource)
    {
        using var doc = PdfDocument.Open(bytes, new PdfOpenOptions { AllowEditing = true });
        var tsa = new TsaClient(new Fetcher(new HttpTransport()), new Uri("https://tsa.example.test/"));
        var afterTimestamp = new PadesValidationData { TrustAnchors = anchors, Intermediates = intermediates, ReferenceTime = now, RevocationSource = revocationSource };
        doc.SignPadesArchive(output, key, certificate, chain, new PadesSignOptions { Timestamp = tsa.GetTimestampAsync }, afterTimestamp);
    }

    internal static PadesSignOptions TimestampOption()
    {
        var tsa = new TsaClient(new Fetcher(new HttpTransport()), new Uri("https://tsa.example.test/"));
        return new PadesSignOptions { Level = PadesLevel.Timestamped, Timestamp = tsa.GetTimestampAsync };
    }

    internal static SignedData SignDigest(Stream ranges, Certificate certificate, ISigningKey key, IReadOnlyList<Certificate> chain)
    {
        var signer = new CmsSignerSpec { Certificate = certificate, Key = key };
        HashAlgorithmName hash = SignedData.HashAlgorithmFor(signer);
        byte[] digest = SignedData.HashContent(DigestNames.GetOid(hash), ranges);
        return SignedData.CreateDetachedFromDigest(digest, hash, [signer], new SignedDataOptions { Certificates = [.. chain] });
    }

    internal static CmsSignerSpec TypedKey(System.Security.Cryptography.X509Certificates.X509Certificate2 x509, Certificate cert) =>
        new() { Certificate = cert, Key = PrivateKey.SigningKeyFromCertificate(x509) };

    internal static void StraightLine(PdfDocument doc, PadesVerifyOptions options)
    {
        PadesTimestamp stamp = doc.VerifyPades(options).Signatures[0].Timestamps[0];
        RecursiveAI.OneCrypto.Tsp.TimeStampReport report = stamp.RequireReport();
        _ = report.RequireToken();
        using Stream signed = doc.GetSignatures()[0].OpenSignedDataOrThrow();
    }

    internal static DistinguishedName Names(ReadOnlyMemory<byte> der) => DistinguishedName.FromDer(der).Rdns.Count > 0 ? DistinguishedName.FromString("CN=Example,O=Org") : DistinguishedName.Parse("CN=Example");
}
