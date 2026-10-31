using OneCrypto.Tests.Support;
using OneCrypto.Tests.Validation;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.Wire.Cms;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Cms;

/// <summary>
/// The optional chain step of SignedData verification: each signer's certificate goes through the path validator, with the message's own certificates and
/// revocation data added as untrusted material. Without <see cref="SignedDataVerifyOptions.Chain"/> nothing about trust is claimed.
/// </summary>
public class SignedDataChainTests
{
    private static readonly DateTimeOffset Now = RNode.Now;
    private static readonly byte[] Content = "signed under a chain"u8.ToArray();

    // root -> CA -> leaf. The leaf is the CMS signer.
    private sealed class Pki : IDisposable
    {
        public Pki(DateTimeOffset? leafNotAfter = null)
        {
            Root = RNode.Make("Root", null, true);
            Ca = RNode.Make("CA", Root, true);
            Leaf = RNode.Make("signer", Ca, false, notAfter: leafNotAfter);
        }

        public RNode Root { get; }

        public RNode Ca { get; }

        public RNode Leaf { get; }

        public static CmsSignerSpec Spec(RNode n) => new() { Certificate = n.Certificate, Signer = n.Signer };

        public SignedData Sign(SignedDataOptions? options = null) =>
            SignedData.Create(Content, [Spec(Leaf)], options ?? new SignedDataOptions { Certificates = [Ca.Certificate] });

        public void Dispose()
        {
            Leaf.Dispose();
            Ca.Dispose();
            Root.Dispose();
        }
    }

    private static ValidationOptions Chain(RNode anchor, IEnumerable<Certificate>? pool = null, RevocationData? revocation = null, RevocationScope scope = RevocationScope.None, DateTimeOffset? at = null, bool fatal = true) => new()
    {
        TrustAnchors = [TrustAnchor.FromCertificate(anchor.Certificate)],
        Intermediates = [.. pool ?? []],
        ReferenceTime = at ?? Now,
        Revocation = revocation,
        RevocationRequired = scope,
        UnknownRevocationIsFatal = fatal,
    };

    private static SignedDataReport Verify(SignedData sd, ValidationOptions? chain) => SignedData.Parse(sd.Encoded).Verify(new SignedDataVerifyOptions { Chain = chain });

    private static string Why(SignedDataReport r) => string.Join("; ", r.Signers.SelectMany(s => s.Checks).Where(c => c.Status != CmsCheckStatus.Passed && c.Status != CmsCheckStatus.NotApplicable).Select(c => c.Rule + ": " + c.Reason));

    private static SignedData WithRevocationElement(SignedData sd, byte[] element)
    {
        Assert.True(Asn1Element.TryRead(sd.Encoded, out Asn1Element ci, out _, out _));
        var top = new List<Asn1Element>();
        Assert.True(Asn1Element.TryChildren(ci, 8, top, out _)); // contentType, [0]
        var wrapper = new List<Asn1Element>();
        Assert.True(Asn1Element.TryChildren(top[1], 8, wrapper, out _));
        var fields = new List<Asn1Element>();
        Assert.True(Asn1Element.TryChildren(wrapper[0], 16, fields, out _));
        var parts = fields.Select(f => f.Encoded.ToArray()).ToList();
        parts.Insert(parts.Count - 1, element); // revocation info goes after the certificates and before the signerInfos
        byte[] signedData = DerWriter.Sequence([.. parts]);
        return SignedData.Parse(DerWriter.Sequence(DerWriter.Oid(CmsOids.SignedData), DerWriter.Context(0, signedData)));
    }

    [Fact]
    public void WithoutChainOptionsNothingAboutTrustIsClaimed()
    {
        using var pki = new Pki();
        SignedDataReport r = Verify(pki.Sign(), null);
        Assert.True(r.IsValid, Why(r));
        Assert.Null(r.Signers[0].Chain);
        Assert.Null(r.Signers[0].Find("chain"));
    }

    [Fact]
    public void ValidChainWithTheIntermediateOnlyInTheMessage()
    {
        using var pki = new Pki();
        // The pool is empty: the CA is found among the message's own certificates.
        SignedDataReport r = Verify(pki.Sign(), Chain(pki.Root));
        Assert.True(r.IsValid, Why(r));
        SignerReport s = r.Signers[0];
        Assert.Equal(CmsCheckStatus.Passed, s.Find("chain")!.Status);
        Assert.True(s.Chain!.IsValid);
        Assert.Equal(2, s.Chain.SelectedPath!.Certificates.Length);
        Assert.Equal(pki.Ca.Certificate, s.Chain.SelectedPath.Certificates[0].Certificate);

        // The intermediate missing from both the message and the pool: no path.
        SignedData bare = pki.Sign(new SignedDataOptions());
        r = Verify(bare, Chain(pki.Root));
        Assert.False(r.IsValid);
        Assert.Equal(CmsCheckStatus.Failed, r.Signers[0].Find("chain")!.Status);
        Assert.Equal(CmsCheckStatus.Passed, r.Signers[0].Find("signature")!.Status); // the signature itself is fine

        // Supplying it through the options completes the path.
        r = Verify(bare, Chain(pki.Root, [pki.Ca.Certificate]));
        Assert.True(r.IsValid, Why(r));
    }

    [Fact]
    public void UntrustedAnchorFails()
    {
        using var pki = new Pki();
        using var other = RNode.Make("OtherRoot", null, true);
        SignedDataReport r = Verify(pki.Sign(), Chain(other));
        Assert.False(r.IsValid);
        SignerReport s = r.Signers[0];
        Assert.Equal(CmsCheckStatus.Failed, s.Find("chain")!.Status);
        Assert.Equal(ValidationVerdict.Invalid, s.Chain!.Verdict);
        Assert.Equal(ValidationRule.PathBuilding, s.Chain.DecidingRule!.Rule);
        Assert.Equal(CmsCheckStatus.Passed, s.Find("signature")!.Status);
    }

    [Fact]
    public void ExpiredSignerIsJudgedAtTheReferenceTimeNotTheClaimedSigningTime()
    {
        using var pki = new Pki(leafNotAfter: Now.AddDays(-30));
        SignedData sd = SignedData.Create(Content, [new CmsSignerSpec { Certificate = pki.Leaf.Certificate, Signer = pki.Leaf.Signer, SigningTime = Now.AddDays(-60) }], new SignedDataOptions { Certificates = [pki.Ca.Certificate] });

        // At the reference time the certificate has expired, whatever the signer claims about when it signed.
        SignedDataReport r = Verify(sd, Chain(pki.Root, at: Now));
        Assert.False(r.IsValid);
        Assert.Equal(CmsCheckStatus.Failed, r.Signers[0].Find("chain")!.Status);
        Assert.Equal(ValidationRule.Validity, r.Signers[0].Chain!.DecidingRule!.Rule);

        // Asked about an instant when it was valid (a proven signing time, such as a time-stamp's genTime), the same message is valid.
        r = Verify(sd, Chain(pki.Root, at: Now.AddDays(-60)));
        Assert.True(r.IsValid, Why(r));
    }

    [Fact]
    public void RevokedSignerThroughACrlCarriedInTheMessage()
    {
        using var pki = new Pki();
        CertificateRevocationList listed = RNode.Crl(pki.Ca, [new RevokedCertificateInfo(RNode.Serial(pki.Leaf.Certificate), Now.AddDays(-2), RevocationReason.KeyCompromise)]);
        SignedData sd = pki.Sign(new SignedDataOptions { Certificates = [pki.Ca.Certificate], Crls = [listed] });

        SignedDataReport r = Verify(sd, Chain(pki.Root, scope: RevocationScope.EndEntity));
        Assert.False(r.IsValid);
        Assert.Equal(CmsCheckStatus.Failed, r.Signers[0].Find("chain")!.Status);
        Assert.Equal(RevocationStatus.Revoked, r.Signers[0].Chain!.RevocationSummary);

        // A CRL that does not list it makes the revocation status good.
        CertificateRevocationList clean = RNode.Crl(pki.Ca);
        r = Verify(pki.Sign(new SignedDataOptions { Certificates = [pki.Ca.Certificate], Crls = [clean] }), Chain(pki.Root, scope: RevocationScope.EndEntity));
        Assert.True(r.IsValid, Why(r));
        Assert.Equal(RevocationStatus.Good, r.Signers[0].Chain!.SelectedPath!.Certificates[^1].Revocation.Status);
    }

    [Fact]
    public void RevokedSignerThroughOcspSuppliedByTheCaller()
    {
        using var pki = new Pki();
        OcspCertId id = OcspCertId.Create(pki.Leaf.Certificate, pki.Ca.Certificate);
        OcspBasicResponse Answer(OcspCertStatus status) => OcspResponseBuilder.CreateSuccessful(
            new OcspResponseOptions
            {
                Responder = new OcspResponderId(pki.Ca.Certificate.Subject),
                ProducedAt = Now.AddHours(-1),
                Responses = [new OcspSingleResponseInfo(id, status, Now.AddHours(-1), Now.AddDays(1), status == OcspCertStatus.Revoked ? Now.AddDays(-3) : null, status == OcspCertStatus.Revoked ? RevocationReason.KeyCompromise : null)],
            },
            pki.Ca.Signer).BasicResponse!;

        SignedData sd = pki.Sign();
        SignedDataReport r = Verify(sd, Chain(pki.Root, revocation: new RevocationData { OcspResponses = [Answer(OcspCertStatus.Revoked)] }, scope: RevocationScope.EndEntity));
        Assert.False(r.IsValid);
        Assert.Equal(RevocationStatus.Revoked, r.Signers[0].Chain!.RevocationSummary);

        r = Verify(sd, Chain(pki.Root, revocation: new RevocationData { OcspResponses = [Answer(OcspCertStatus.Good)] }, scope: RevocationScope.EndEntity));
        Assert.True(r.IsValid, Why(r));
        Assert.Equal(RevocationStatus.Good, r.Signers[0].Chain!.SelectedPath!.Certificates[^1].Revocation.Status);
    }

    [Fact]
    public void OcspResponseCarriedInTheMessageRevocationSetIsUsed()
    {
        using var pki = new Pki();
        OcspCertId id = OcspCertId.Create(pki.Leaf.Certificate, pki.Ca.Certificate);
        OcspResponse resp = OcspResponseBuilder.CreateSuccessful(
            new OcspResponseOptions
            {
                Responder = new OcspResponderId(pki.Ca.Certificate.Subject),
                ProducedAt = Now.AddHours(-1),
                Responses = [new OcspSingleResponseInfo(id, OcspCertStatus.Revoked, Now.AddHours(-1), Now.AddDays(1), Now.AddDays(-3), RevocationReason.KeyCompromise)],
            },
            pki.Ca.Signer);
        // RFC 5652 §5.1: crls [1] IMPLICIT SET OF { other [1] IMPLICIT OtherRevocationInfoFormat { id-ri-ocsp-response, OCSPResponse } }
        byte[] element = DerWriter.Tlv(0xA1, DerWriter.Tlv(0xA1, [.. DerWriter.Oid("1.3.6.1.5.5.7.16.2"), .. resp.Encoded.ToArray()]));
        SignedData sd = WithRevocationElement(pki.Sign(), element);
        Assert.Single(sd.RevocationElements);

        SignedDataReport r = Verify(sd, Chain(pki.Root, scope: RevocationScope.EndEntity));
        Assert.False(r.IsValid);
        Assert.Equal(RevocationStatus.Revoked, r.Signers[0].Chain!.RevocationSummary);
    }

    [Fact]
    public void RequiredRevocationWithNoDataIsUndecidedUnlessTheCallerOptsOut()
    {
        using var pki = new Pki();
        SignedData sd = pki.Sign();
        SignedDataReport r = Verify(sd, Chain(pki.Root, scope: RevocationScope.EndEntity));
        Assert.False(r.IsValid);
        Assert.Equal(CmsCheckStatus.Unsupported, r.Signers[0].Find("chain")!.Status);
        Assert.Equal(ValidationVerdict.Indeterminate, r.Signers[0].Chain!.Verdict);

        r = Verify(sd, Chain(pki.Root, scope: RevocationScope.EndEntity, fatal: false));
        Assert.True(r.IsValid, Why(r));
        Assert.Equal(CmsCheckStatus.Warning, r.Signers[0].Find("chain")!.Status);
        Assert.Equal(RevocationStatus.Unknown, r.Signers[0].Chain!.RevocationSummary);
    }

    [Fact]
    public void SubstitutedSignerCertificateIsCaughtByTheEssSigningCertificate()
    {
        using var pki = new Pki();
        // A second CA with the first one's name, also trusted-root-signed. It re-certifies the signer's key under the same issuer name and serial number,
        // so the SignerIdentifier still matches and the path validates; only the signing-certificate attribute names the original certificate by hash.
        using var ca2 = RNode.Make("CA", pki.Root, true, subject: pki.Ca.Certificate.Subject);
        Certificate substitute = CertificateBuilder.Create(
            new CertificateOptions
            {
                Subject = pki.Leaf.Certificate.Subject,
                PublicKey = pki.Leaf.Certificate.PublicKey,
                NotBefore = Now.AddYears(-1),
                NotAfter = Now.AddYears(1),
                SerialNumber = pki.Leaf.Certificate.SerialNumber,
                Extensions = [Extension.Create(new BasicConstraints(false), true)],
            },
            ca2.Certificate,
            ca2.Signer);
        Assert.NotEqual(pki.Leaf.Certificate, substitute);

        SignedData sd = pki.Sign(new SignedDataOptions { IncludeSignerCertificates = false, Certificates = [substitute, ca2.Certificate] });
        SignedDataReport r = Verify(sd, Chain(pki.Root));
        SignerReport s = r.Signers[0];
        Assert.Equal(substitute, s.Certificate);
        Assert.Equal(CmsCheckStatus.Passed, s.Find("chain")!.Status); // the substitute chains to the trusted root
        Assert.Equal(CmsCheckStatus.Passed, s.Find("signature")!.Status); // and it holds the same key
        Assert.Equal(CmsCheckStatus.Failed, s.Find("signing-certificate")!.Status);
        Assert.False(r.IsValid);
    }

    [Fact]
    public void ExtraSignerWithAnUntrustedCertificateInvalidatesTheMessageNotTheGoodSigner()
    {
        using var pki = new Pki();
        using var rogue = RNode.Make("rogue", null, false);
        SignedData sd = SignedData.Create(Content, [Pki.Spec(pki.Leaf), Pki.Spec(rogue)], new SignedDataOptions { Certificates = [pki.Ca.Certificate] });
        SignedDataReport r = Verify(sd, Chain(pki.Root));
        Assert.False(r.IsValid);
        Assert.True(r.Signers[0].IsValid, Why(r));
        Assert.False(r.Signers[1].IsValid);
        Assert.Equal(CmsCheckStatus.Passed, r.Signers[1].Find("signature")!.Status);
        Assert.Equal(CmsCheckStatus.Failed, r.Signers[1].Find("chain")!.Status);
    }

    [Fact]
    public void CountersignaturesAreChainValidatedToo()
    {
        using var pki = new Pki();
        using var good = RNode.Make("countersigner", pki.Ca, false);
        using var rogue = RNode.Make("rogue", null, false);
        SignedData sd = pki.Sign();

        SignedData WithCounter(RNode who)
        {
            CmsAttributeEntry counter = SignedData.CreateCountersignature(sd.Signers[0], Pki.Spec(who));
            return sd.WithUnsignedAttribute(0, counter, [who.Certificate]);
        }

        SignedDataReport r = Verify(WithCounter(good), Chain(pki.Root));
        Assert.True(r.IsValid, Why(r));
        Assert.Equal(CmsCheckStatus.Passed, r.Signers[0].Countersignatures[0].Find("chain")!.Status);

        r = Verify(WithCounter(rogue), Chain(pki.Root));
        Assert.False(r.IsValid);
        Assert.Equal(CmsCheckStatus.Failed, r.Signers[0].Countersignatures[0].Find("chain")!.Status);
        Assert.Equal(CmsCheckStatus.Failed, r.Signers[0].Find("countersignatures")!.Status);
    }

    [Fact]
    public void DecoyCertificatesInTheMessageCannotCreateTrust()
    {
        using var pki = new Pki();
        using var rogueRoot = RNode.Make("Root", null, true); // the trusted root's name, another key
        using var rogueCa = RNode.Make("CA", rogueRoot, true, subject: pki.Ca.Certificate.Subject);
        using var rogueLeaf = RNode.Make("signer", rogueCa, false, subject: pki.Leaf.Certificate.Subject);

        // An attacker signs with their own key under their own look-alike chain; the real root does not vouch for it.
        SignedData forged = SignedData.Create(Content, [Pki.Spec(rogueLeaf)], new SignedDataOptions { Certificates = [rogueCa.Certificate, rogueRoot.Certificate] });
        SignedDataReport r = Verify(forged, Chain(pki.Root));
        Assert.False(r.IsValid);
        Assert.Equal(CmsCheckStatus.Failed, r.Signers[0].Find("chain")!.Status);

        // Look-alikes beside the genuine chain change nothing for the genuine signer.
        SignedData genuine = pki.Sign(new SignedDataOptions { Certificates = [rogueRoot.Certificate, rogueCa.Certificate, pki.Ca.Certificate] });
        r = Verify(genuine, Chain(pki.Root));
        Assert.True(r.IsValid, Why(r));
    }

    [Fact]
    public void ChainFailureDoesNotHideAnInvalidSignature()
    {
        using var pki = new Pki();
        byte[] enc = pki.Sign().Encoded.ToArray();
        enc[enc.AsSpan().IndexOf(Content)] ^= 1;
        SignedDataReport r = SignedData.Parse(enc).Verify(new SignedDataVerifyOptions { Chain = Chain(pki.Root) });
        Assert.False(r.IsValid);
        Assert.Equal(CmsCheckStatus.Passed, r.Signers[0].Find("chain")!.Status);
        Assert.Equal(CmsCheckStatus.Failed, r.Signers[0].Find("message-digest")!.Status);
    }

    [Fact]
    public void OpenSslSignaturesWithChainsAreValidatedAndAgree()
    {
        OpenSslTool.RequireOrSkip();
        using var pki = new Pki();
        using var other = RNode.Make("OtherRoot", null, true);
        string dir = OpenSslSignedDataTests.Dir("chain");
        string P(string n) => Path.Combine(dir, n);
        File.WriteAllText(P("root.pem"), pki.Root.Certificate.ToPem());
        File.WriteAllText(P("other.pem"), other.Certificate.ToPem());
        File.WriteAllText(P("ca.pem"), pki.Ca.Certificate.ToPem());
        File.WriteAllText(P("leaf.pem"), pki.Leaf.Certificate.ToPem());
        File.WriteAllText(P("leaf.key"), pki.Leaf.KeyPem);
        File.WriteAllBytes(P("content.bin"), Content);

        // openssl signs with the leaf and carries the CA (-certfile) in the message.
        OpenSslSignedDataTests.Ok(OpenSslTool.Run("cms", "-sign", "-nodetach", "-binary", "-outform", "DER", "-in", P("content.bin"), "-signer", P("leaf.pem"), "-inkey", P("leaf.key"), "-certfile", P("ca.pem"), "-out", P("with-ca.der")), "openssl cms -sign");
        OpenSslSignedDataTests.Ok(OpenSslTool.Run("cms", "-sign", "-nodetach", "-binary", "-outform", "DER", "-in", P("content.bin"), "-signer", P("leaf.pem"), "-inkey", P("leaf.key"), "-out", P("no-ca.der")), "openssl cms -sign");
        SignedData withCa = SignedData.Parse(File.ReadAllBytes(P("with-ca.der")));
        SignedData noCa = SignedData.Parse(File.ReadAllBytes(P("no-ca.der")));

        // Ours.
        Assert.True(Verify(withCa, Chain(pki.Root)).IsValid, Why(Verify(withCa, Chain(pki.Root))));
        Assert.False(Verify(withCa, Chain(other)).IsValid);
        Assert.False(Verify(noCa, Chain(pki.Root)).IsValid);
        Assert.True(Verify(noCa, Chain(pki.Root, [pki.Ca.Certificate])).IsValid);

        // openssl's verdicts on the same files (any purpose: the test leaf is a TLS-style certificate).
        string[] common = ["cms", "-verify", "-inform", "DER", "-binary", "-purpose", "any", "-out", P("out.bin")];
        Assert.Equal(0, OpenSslTool.Run([.. common, "-in", P("with-ca.der"), "-CAfile", P("root.pem")]).Code);
        Assert.NotEqual(0, OpenSslTool.Run([.. common, "-in", P("with-ca.der"), "-CAfile", P("other.pem")]).Code);
        Assert.NotEqual(0, OpenSslTool.Run([.. common, "-in", P("no-ca.der"), "-CAfile", P("root.pem")]).Code);
        Assert.Equal(0, OpenSslTool.Run([.. common, "-in", P("no-ca.der"), "-CAfile", P("root.pem"), "-certfile", P("ca.pem")]).Code);

        // And a message we build is accepted by openssl against the same root.
        File.WriteAllBytes(P("ours.der"), pki.Sign().Encoded.ToArray());
        Assert.Equal(0, OpenSslTool.Run([.. common, "-in", P("ours.der"), "-CAfile", P("root.pem")]).Code);
    }

    [Fact]
    public void TokenWithIndefiniteLengthsIsEmbeddedAsDerAndTheSignatureStaysValid()
    {
        using var pki = new Pki();
        using var tsa = RNode.Make("tsa", pki.Ca, false);
        // A stand-in for a time-stamp token: a SignedData some authorities write with indefinite lengths.
        SignedData token = SignedData.Create("stamped"u8.ToArray(), [Pki.Spec(tsa)], new SignedDataOptions { ContentType = CmsOids.TstInfo });
        byte[] der = token.Encoded.ToArray();
        byte[] ber = Indefinite(der, 3);
        Assert.NotEqual(der, ber);
        Assert.True(BerToDer.TryConvert(ber, out byte[] converted));
        Assert.Equal(der, converted);

        SignedData sd = pki.Sign();
        SignedData stamped = sd.WithUnsignedAttribute(0, CmsAttributeEntry.Create(CmsOids.SignatureTimeStampToken, converted), [tsa.Certificate]);
        SignedDataReport r = Verify(stamped, Chain(pki.Root));
        Assert.True(r.IsValid, Why(r));
        Assert.True(stamped.Encoded.Span.IndexOf(der) >= 0, "the stamped bytes are embedded verbatim as DER");
    }

    private static byte[] Indefinite(byte[] der, int levels)
    {
        Assert.True(Asn1Element.TryRead(der, out Asn1Element e, out _, out _));
        if (levels == 0 || !e.Constructed)
        {
            return der;
        }

        var kids = new List<Asn1Element>();
        Assert.True(Asn1Element.TryChildren(e, 1000, kids, out _));
        var body = new List<byte> { der[0], 0x80 };
        for (int i = 0; i < kids.Count; i++)
        {
            body.AddRange(i == kids.Count - 1 ? Indefinite(kids[i].Encoded.ToArray(), levels - 1) : kids[i].Encoded.ToArray());
        }

        body.Add(0);
        body.Add(0);
        return [.. body];
    }
}
