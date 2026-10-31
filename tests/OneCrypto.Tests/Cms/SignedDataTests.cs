using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Wire.Cms;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Cms;

/// <summary>Building and verifying SignedData across the signature kinds, attribute forms, signer counts and damaged inputs.</summary>
public class SignedDataTests
{
    private static readonly byte[] Content = "Hello CMS world"u8.ToArray();

    public static IEnumerable<object[]> Matrix()
    {
        foreach (SigKind kind in Enum.GetValues<SigKind>())
        {
            foreach (bool attrs in new[] { true, false })
            {
                foreach (bool detached in new[] { true, false })
                {
                    yield return [kind, attrs, detached];
                }
            }
        }
    }

    [Theory]
    [MemberData(nameof(Matrix))]
    public void BuiltMessagesVerify(SigKind kind, bool attrs, bool detached)
    {
        Assert.SkipUnless(CmsKeys.IsAvailable(kind), kind + " is not available on this platform");
        SignerKit k = CmsKeys.Get(kind);
        SignedData made = SignedData.Create(Content, [k.Spec(b => b.SignedAttributes = attrs)], new SignedDataOptions { Detached = detached });
        SignedData sd = SignedData.Parse(made.Encoded);
        Assert.Equal(!detached, sd.HasEncapsulatedContent);
        SignedDataReport report = detached ? sd.Verify(Content) : sd.Verify();
        Assert.True(report.IsValid, Describe(report));
        SignerReport s = Assert.Single(report.Signers);
        Assert.Equal(CmsCheckStatus.Passed, s.Find("signature")!.Status);
        Assert.Equal(k.Certificate, s.Certificate);
        if (attrs)
        {
            Assert.Equal(CmsCheckStatus.Passed, s.Find("message-digest")!.Status);
            Assert.Equal(CmsCheckStatus.Passed, s.Find("signing-certificate")!.Status);
            Assert.Equal(CmsKeys.SigningTime, s.SigningTime);
        }
        else
        {
            Assert.Null(sd.Signers[0].SignedAttributes);
        }
    }

    [Theory]
    [InlineData(SigKind.Rsa, true)]
    [InlineData(SigKind.P256, true)]
    [InlineData(SigKind.Rsa, false)]
    [InlineData(SigKind.Ed25519, false)]
    public void TamperingIsReported(SigKind kind, bool attrs)
    {
        SignerKit k = CmsKeys.Get(kind);
        SignedData made = SignedData.Create(Content, [k.Spec(b => b.SignedAttributes = attrs)]);
        byte[] enc = made.Encoded.ToArray();

        // The content.
        byte[] bad = (byte[])enc.Clone();
        bad[bad.AsSpan().IndexOf(Content)] ^= 1;
        SignedDataReport r = SignedData.Parse(bad).Verify();
        Assert.False(r.IsValid);
        if (attrs)
        {
            Assert.Equal(CmsCheckStatus.Failed, r.Signers[0].Find("message-digest")!.Status);
        }
        else
        {
            Assert.Equal(CmsCheckStatus.Failed, r.Signers[0].Find("signature")!.Status);
        }

        // The signature value.
        SignerInfo si = made.Signers[0];
        bad = (byte[])enc.Clone();
        int at = bad.AsSpan().LastIndexOf(si.Signature.Span);
        bad[at + 5] ^= 0x10;
        r = SignedData.Parse(bad).Verify();
        Assert.False(r.IsValid);
        Assert.Equal(CmsCheckStatus.Failed, r.Signers[0].Find("signature")!.Status);

        // A signed attribute.
        if (attrs)
        {
            bad = (byte[])enc.Clone();
            ReadOnlySpan<byte> time = si.FindSigned(CmsOids.SigningTime)!.Values[0].Span;
            bad[bad.AsSpan().IndexOf(time) + 4] ^= 1;
            r = SignedData.Parse(bad).Verify();
            Assert.False(r.IsValid);
            Assert.Equal(CmsCheckStatus.Failed, r.Signers[0].Find("signature")!.Status);
        }
    }

    [Fact]
    public void EveryByteDamagedGivesAReportOrATypedError()
    {
        byte[] enc = SignedData.Create(Content, [CmsKeys.Get(SigKind.P256).Spec()]).Encoded.ToArray();
        for (int i = 0; i < enc.Length; i++)
        {
            byte[] bad = (byte[])enc.Clone();
            bad[i] ^= 0xFF;
            if (SignedData.TryParse(bad, out SignedData? sd))
            {
                SignedDataReport r = sd!.Verify();
                Assert.False(r.IsValid && i > 4 && !bad.AsSpan().SequenceEqual(enc) && IsSignedRegion(enc, i) , "byte " + i);
            }
        }
    }

    // The bytes covered by the signature or the digest: the content and the signed attributes.
    private static bool IsSignedRegion(byte[] enc, int i)
    {
        SignedData sd = SignedData.Parse(enc);
        SignerInfo si = sd.Signers[0];
        int attrsAt = enc.AsSpan().IndexOf(si.SignedAttributesEncoded.Span);
        int contentAt = enc.AsSpan().IndexOf(sd.EncapsulatedContent.Span);
        return (i >= attrsAt + 1 && i < attrsAt + si.SignedAttributesEncoded.Length && i != attrsAt + 1) || (i >= contentAt && i < contentAt + sd.EncapsulatedContent.Length);
    }

    [Fact]
    public void ManySignersAreReportedOneByOne()
    {
        SignerKit a = CmsKeys.Get(SigKind.Rsa), b = CmsKeys.Get(SigKind.P384), c = CmsKeys.Get(SigKind.Ed25519);
        SignedData made = SignedData.Create(Content, [a.Spec(), b.Spec(x => x.Identifier = CmsIdentifierKind.SubjectKeyIdentifier), c.Spec()]);
        SignedData sd = SignedData.Parse(made.Encoded);
        Assert.Equal(3, sd.Signers.Count);
        Assert.Equal(3, sd.Version);
        Assert.Equal(1, sd.Signers[0].Version);
        Assert.Equal(3, sd.Signers[1].Version);
        Assert.Equal(CmsIdentifierKind.SubjectKeyIdentifier, sd.Signers[1].Identifier.Kind);
        Assert.Equal(3, sd.Certificates.Count);
        Assert.True(sd.Verify().IsValid);

        // Spoil only the middle signer's signature: the others stay valid.
        byte[] bad = made.Encoded.ToArray();
        int at = bad.AsSpan().LastIndexOf(sd.Signers[1].Signature.Span);
        bad[at + 8] ^= 1;
        SignedDataReport r = SignedData.Parse(bad).Verify();
        Assert.False(r.IsValid);
        Assert.True(r.Signers[0].IsValid);
        Assert.False(r.Signers[1].IsValid);
        Assert.True(r.Signers[2].IsValid);
    }

    [Fact]
    public void DigestFollowsTheSignatureAlgorithm()
    {
        Assert.Equal(KnownOids.Sha256, SignedData.Create(Content, [CmsKeys.Get(SigKind.Rsa).Spec()]).Signers[0].DigestAlgorithm.Oid);
        Assert.Equal(KnownOids.Sha384, SignedData.Create(Content, [CmsKeys.Get(SigKind.P384).Spec()]).Signers[0].DigestAlgorithm.Oid);
        Assert.Equal(KnownOids.Sha512, SignedData.Create(Content, [CmsKeys.Get(SigKind.P521).Spec()]).Signers[0].DigestAlgorithm.Oid);
        Assert.Equal(KnownOids.Sha512, SignedData.Create(Content, [CmsKeys.Get(SigKind.Ed25519).Spec()]).Signers[0].DigestAlgorithm.Oid);
        Assert.Equal(CmsOids.Shake256, SignedData.Create(Content, [CmsKeys.Get(SigKind.Ed448).Spec()]).Signers[0].DigestAlgorithm.Oid);
        Assert.Throws<ArgumentException>(() => SignedData.Create(Content, [CmsKeys.Get(SigKind.P256).Spec(b => b.DigestAlgorithm = KnownOids.Sha512)]));
    }

    [Fact]
    public void Sha1IsFlaggedButVerifies()
    {
        using var rsa = RSA.Create(2048);
        X509Signer signer = X509Signer.FromRsa(rsa, HashAlgorithmName.SHA1);
        // SHA-1 is refused for new data under the default policy; this test plays an old signer, so it asks for a policy that allows it.
        RecursiveAI.OneCrypto.Policy.CryptoPolicy legacy = RecursiveAI.OneCrypto.Policy.CryptoPolicy.Standard with { HashRules = [] };
        Certificate cert = CmsKeys.SelfSigned("Old SHA-1", signer, policy: legacy);
        SignedData sd = SignedData.Create(Content, [new CmsSignerSpec { Certificate = cert, Signer = signer }], new SignedDataOptions { Policy = legacy });
        SignedDataReport r = sd.Verify();
        Assert.True(r.IsValid);
        Assert.Equal(CmsCheckStatus.Warning, r.Signers[0].Find("digest-algorithm")!.Status);
    }

    [Fact]
    public void CertificateLookupAndKeyUsage()
    {
        SignerKit k = CmsKeys.Get(SigKind.P256);
        SignedData noCerts = SignedData.Create(Content, [k.Spec()], new SignedDataOptions { IncludeSignerCertificates = false });
        Assert.Empty(noCerts.Certificates);
        SignedDataReport r = noCerts.Verify();
        Assert.False(r.IsValid);
        Assert.Equal(CmsCheckStatus.Failed, r.Signers[0].Find("signer-certificate")!.Status);
        Assert.True(noCerts.Verify(new SignedDataVerifyOptions { ExtraCertificates = [k.Certificate] }).IsValid);

        // A certificate that may only encipher keys must not sign.
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Signer s = X509Signer.FromECDsa(ec);
        Certificate keyOnly = CmsKeys.SelfSigned("Key only", s, KeyUsages.KeyEncipherment);
        SignedData bad = SignedData.Create(Content, [new CmsSignerSpec { Certificate = keyOnly, Signer = s }]);
        r = bad.Verify();
        Assert.False(r.IsValid);
        Assert.Equal(CmsCheckStatus.Failed, r.Signers[0].Find("key-usage")!.Status);
        Assert.True(bad.Verify(new SignedDataVerifyOptions { AnyOfKeyUsages = KeyUsages.None }).IsValid);

        // The caller decides which purposes count.
        Certificate tsOnly = CmsKeys.SelfSigned("Stamper", s, eku: [KnownOids.TimeStamping]);
        SignedData stamp = SignedData.Create(Content, [new CmsSignerSpec { Certificate = tsOnly, Signer = s }]);
        Assert.True(stamp.Verify().IsValid);
        Assert.False(stamp.Verify(new SignedDataVerifyOptions { RequiredExtendedKeyUsage = KnownOids.EmailProtection }).IsValid);
        Assert.True(stamp.Verify(new SignedDataVerifyOptions { RequiredExtendedKeyUsage = KnownOids.TimeStamping }).IsValid);
    }

    [Fact]
    public void WrongKeyForTheCertificateFails()
    {
        SignerKit a = CmsKeys.Get(SigKind.P256), b = CmsKeys.Get(SigKind.P384);
        // The signer b signs but names a's certificate.
        SignedData sd = SignedData.Create(Content, [new CmsSignerSpec { Certificate = a.Certificate, Signer = b.Signer }]);
        SignedDataReport r = sd.Verify();
        Assert.False(r.IsValid);
        Assert.Equal(CmsCheckStatus.Failed, r.Signers[0].Find("signature")!.Status);
    }

    [Fact]
    public void SigningCertificateAttributeMustNameTheSigner()
    {
        SignerKit a = CmsKeys.Get(SigKind.P256), b = CmsKeys.Get(SigKind.P384);
        // Signed by a, with the ESS attribute of b's certificate.
        CmsAttributeEntry other = SignedData.Create(Content, [b.Spec()]).Signers[0].FindSigned(CmsOids.SigningCertificateV2)!;
        SignedData sd = SignedData.Create(Content, [a.Spec(x =>
        {
            x.SigningCertificate = EssSigningCertificate.None;
            x.AdditionalSignedAttributes = [other];
        })]);
        SignedDataReport r = sd.Verify();
        Assert.False(r.IsValid);
        Assert.Equal(CmsCheckStatus.Failed, r.Signers[0].Find("signing-certificate")!.Status);

        // Version 1 of the attribute works too.
        SignedData v1 = SignedData.Create(Content, [a.Spec(x => x.SigningCertificate = EssSigningCertificate.V1)]);
        Assert.NotNull(v1.Signers[0].FindSigned(CmsOids.SigningCertificate));
        Assert.True(v1.Verify().IsValid);
        SignedData none = SignedData.Create(Content, [a.Spec(x => x.SigningCertificate = EssSigningCertificate.None)]);
        Assert.Equal(CmsCheckStatus.NotApplicable, none.Verify().Signers[0].Find("signing-certificate")!.Status);
    }

    [Fact]
    public void CountersignaturesAreCheckedWithTheirParent()
    {
        SignerKit a = CmsKeys.Get(SigKind.Rsa), c = CmsKeys.Get(SigKind.P256);
        SignedData made = SignedData.Create(Content, [a.Spec()]);
        CmsAttributeEntry counter = SignedData.CreateCountersignature(made.Signers[0], c.Spec());
        SignedData both = made.WithUnsignedAttribute(0, counter, [c.Certificate]);
        SignedDataReport r = SignedData.Parse(both.Encoded).Verify();
        Assert.True(r.IsValid, Describe(r));
        SignerReport cs = Assert.Single(r.Signers[0].Countersignatures);
        Assert.Equal(c.Certificate, cs.Certificate);
        Assert.Null(cs.Find("content-type") is { Status: CmsCheckStatus.Failed } ? "failed" : null);

        // The countersignature covers the parent's signature value: damage it and the counter fails with it.
        byte[] bad = both.Encoded.ToArray();
        int at = bad.AsSpan().IndexOf(made.Signers[0].Signature.Span);
        bad[at + 3] ^= 1;
        r = SignedData.Parse(bad).Verify();
        Assert.False(r.IsValid);
        Assert.False(r.Signers[0].Countersignatures[0].IsValid);

        // The original signed parts stay byte-identical.
        Assert.True(both.Encoded.Span.IndexOf(made.Signers[0].SignedAttributesEncoded.Span) > 0);
    }

    [Fact]
    public void IndefiniteLengthBerIsAccepted()
    {
        SignedData made = SignedData.Create(Content, [CmsKeys.Get(SigKind.Rsa).Spec()]);
        byte[] ber = Indefinite(made.Encoded.ToArray(), 4);
        Assert.NotEqual(made.Encoded.ToArray(), ber);
        SignedData sd = SignedData.Parse(ber);
        Assert.Equal(Content, sd.EncapsulatedContent.ToArray());
        Assert.True(sd.Verify().IsValid);
    }

    [Fact]
    public void ConstructedOctetStringContentIsJoined()
    {
        SignedData made = SignedData.Create(Content, [CmsKeys.Get(SigKind.Rsa).Spec()]);
        // The OCTET STRING in two pieces, as a streaming signer writes it.
        byte[] pieces = [0x24, 0x80, 0x04, 5, .. Content[..5], 0x04, (byte)(Content.Length - 5), .. Content[5..], 0, 0];
        byte[] body = BuildWithConstructedContent(made, pieces);
        SignedData sd = SignedData.Parse(body);
        Assert.Equal(Content, sd.EncapsulatedContent.ToArray());
        Assert.True(sd.Verify().IsValid);
    }

    private static byte[] BuildWithConstructedContent(SignedData made, byte[] octetStringPieces)
    {
        // ContentInfo { oid, [0] { SignedData } } with every wrapper written as indefinite BER.
        SignerInfo si = made.Signers[0];
        byte[] certs = DerWriter.Retag(DerWriter.SetOf(made.CertificateElements.Select(static c => c.ToArray())), 0xA0);
        byte[] encap = [0x30, 0x80, .. DerWriter.Oid(CmsOids.Data), 0xA0, 0x80, .. octetStringPieces, 0, 0, 0, 0];
        byte[] sd = [0x30, 0x80, .. DerWriter.SignedInteger(1), .. DerWriter.SetOf(made.DigestAlgorithms.Select(static a => a.Encoded.ToArray())), .. encap, .. certs, .. DerWriter.Set(si.Encoded.ToArray()), 0, 0];
        return [0x30, 0x80, .. DerWriter.Oid(CmsOids.SignedData), 0xA0, 0x80, .. sd, 0, 0, 0, 0];
    }

    // Writes the first <levels> nested constructed levels of a DER encoding with indefinite lengths.
    internal static byte[] Indefinite(byte[] der, int levels)
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
            body.AddRange(Indefinite(kids[i].Encoded.ToArray(), levels - 1));
        }

        body.Add(0);
        body.Add(0);
        return body.ToArray();
    }

    [Fact]
    public void TypedErrorsAndLimits()
    {
        Assert.False(SignedData.TryParse(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 }, out _));
        var ex = Assert.Throws<CmsParseException>(() => SignedData.Parse(new byte[] { 1, 2, 3 }));
        Assert.Equal(CmsError.Asn1, ex.Error);
        ContentInfo data = ContentInfo.Create(CmsOids.Data, DerWriter.OctetString(Content));
        var wrongType = Assert.Throws<CmsParseException>(() => SignedData.Parse(data.Encoded));
        Assert.Equal(CmsError.UnexpectedContentType, wrongType.Error);

        SignedData three = SignedData.Create(Content, [CmsKeys.Get(SigKind.Rsa).Spec(), CmsKeys.Get(SigKind.P256).Spec(), CmsKeys.Get(SigKind.P384).Spec()]);
        var limit = Assert.Throws<CmsParseException>(() => SignedData.Parse(three.Encoded, new CmsLimits { MaxSigners = 2 }));
        Assert.Equal(CmsError.LimitExceeded, limit.Error);
        var certLimit = Assert.Throws<CmsParseException>(() => SignedData.Parse(three.Encoded, new CmsLimits { MaxCertificates = 2 }));
        Assert.Equal(CmsError.LimitExceeded, certLimit.Error);
    }

    [Fact]
    public void PdfStylePaddingIsOptIn()
    {
        byte[] enc = SignedData.Create(Content, [CmsKeys.Get(SigKind.P256).Spec()]).Encoded.ToArray();
        byte[] padded = [.. enc, 0, 0, 0, 0];
        Assert.False(SignedData.TryParse(padded, out _));
        Assert.True(SignedData.TryParse(padded, out SignedData? sd, allowTrailingZeros: true));
        Assert.True(sd!.Verify().IsValid);
        byte[] junk = [.. enc, 0, 1];
        Assert.False(SignedData.TryParse(junk, out _, allowTrailingZeros: true));
    }

    [Fact]
    public void ContentTypeIsBoundByTheSignature()
    {
        SignerKit k = CmsKeys.Get(SigKind.P256);
        SignedData tst = SignedData.Create(Content, [k.Spec()], new SignedDataOptions { ContentType = CmsOids.TstInfo });
        Assert.Equal(3, tst.Version);
        Assert.Equal(CmsOids.TstInfo, tst.EncapsulatedContentType);
        Assert.True(tst.Verify().IsValid);
        // Relabel the content: the attribute and the encapsulated type now disagree.
        byte[] enc = tst.Encoded.ToArray();
        byte[] from = DerWriter.Oid(CmsOids.TstInfo), to = DerWriter.Oid("1.2.840.113549.1.9.16.1.5");
        int at = enc.AsSpan().IndexOf(from);
        Assert.Equal(from.Length, to.Length);
        to.CopyTo(enc, at);
        SignedDataReport r = SignedData.Parse(enc).Verify();
        Assert.False(r.IsValid);
        Assert.Equal(CmsCheckStatus.Failed, r.Signers[0].Find("content-type")!.Status);
    }

    [Fact]
    public void ForeignBuiltMessagesVerify()
    {
        // Messages from the independent test kit, which writes the structure by hand.
        TestPki pki = TestPki.Shared;
        foreach ((SigScheme scheme, string hash) in new[] { (SigScheme.RsaPkcs1, "SHA256"), (SigScheme.RsaPss, "SHA384"), (SigScheme.Ecdsa, "SHA384") })
        {
            var h = new HashAlgorithmName(hash);
            byte[] enc = CmsKit.Build(CryptographicOperations.HashData(h, Content), scheme == SigScheme.Ecdsa ? pki.EcSigner : pki.RsaSigner, [pki.RsaSigner, pki.Intermediate],
                new CmsSpec { Hash = h, Scheme = scheme, Cades = true, Embedded = [pki.RsaSigner, pki.EcSigner, pki.Intermediate] }, Content);
            SignedDataReport r = SignedData.Parse(enc).Verify();
            Assert.True(r.IsValid, scheme + ": " + Describe(r));
            Assert.Equal(CmsCheckStatus.Passed, r.Signers[0].Find("signing-certificate")!.Status);
        }
    }

    [Fact]
    public void ForeignBrokenMessagesAreReported()
    {
        TestPki pki = TestPki.Shared;
        byte[] Build(CmsSpec spec) => CmsKit.Build(CryptographicOperations.HashData(HashAlgorithmName.SHA256, Content), pki.RsaSigner, [pki.RsaSigner, pki.Intermediate], spec, Content);

        SignerReport s = SignedData.Parse(Build(new CmsSpec { MessageDigestOverride = new byte[32] })).Verify().Signers[0];
        Assert.Equal(CmsCheckStatus.Failed, s.Find("message-digest")!.Status);
        Assert.Equal(CmsCheckStatus.Passed, s.Find("signature")!.Status);

        s = SignedData.Parse(Build(new CmsSpec { SignatureHashOverride = HashAlgorithmName.SHA384 })).Verify().Signers[0];
        Assert.False(s.IsValid);

        s = SignedData.Parse(Build(new CmsSpec { ClaimedSigner = pki.Stranger, Embedded = [pki.RsaSigner, pki.Stranger] })).Verify().Signers[0];
        Assert.Equal(CmsCheckStatus.Failed, s.Find("signature")!.Status);

        s = SignedData.Parse(Build(new CmsSpec { Cades = true, ClaimedSigner = pki.Stranger, Embedded = [pki.RsaSigner, pki.Stranger] })).Verify().Signers[0];
        Assert.False(s.IsValid);
    }

    [Fact]
    public void MutatedMessagesNeverThrow()
    {
        byte[] cms = SignedData.Create(Content, [CmsKeys.Get(SigKind.Rsa).Spec(), CmsKeys.Get(SigKind.P256).Spec()]).Encoded.ToArray();
        var rng = new Random(1234);
        for (int i = 0; i < 600; i++)
        {
            byte[] copy = (byte[])cms.Clone();
            int n = 1 + rng.Next(3);
            for (int k = 0; k < n; k++)
            {
                copy[rng.Next(copy.Length)] = (byte)rng.Next(256);
            }

            if (SignedData.TryParse(copy, out SignedData? sd))
            {
                _ = sd!.Verify().IsValid;
                _ = sd.Certificates.Count + sd.Crls.Count;
            }
        }
    }

    [Fact]
    public async Task StreamedDetachedVerifyAgreesWithTheBufferedOne()
    {
        SignerKit k = CmsKeys.Get(SigKind.Rsa);
        byte[] big = RandomNumberGenerator.GetBytes(300_000);
        SignedData sd = SignedData.Create(big, [k.Spec(), CmsKeys.Get(SigKind.Ed448).Spec()], new SignedDataOptions { Detached = true });
        Assert.True(sd.Verify(new MemoryStream(big)).Signers[0].IsValid);
        Assert.True((await sd.VerifyAsync(new MemoryStream(big))).Signers[1].IsValid);
        big[1000] ^= 1;
        Assert.False(sd.Verify(new MemoryStream(big)).IsValid);

        // A signature over the content itself cannot be checked from a stream.
        SignedData direct = SignedData.Create(big, [k.Spec(b => b.SignedAttributes = false)], new SignedDataOptions { Detached = true });
        Assert.Equal(CmsCheckStatus.Unsupported, direct.Verify(new MemoryStream(big)).Signers[0].Find("attributes")!.Status);
        Assert.True(direct.Verify(big).IsValid);
    }

    [Fact]
    public void DetachedAndAttachedAreNotConfused()
    {
        SignerKit k = CmsKeys.Get(SigKind.P256);
        SignedData attached = SignedData.Create(Content, [k.Spec()]);
        SignedData detached = SignedData.Create(Content, [k.Spec()], new SignedDataOptions { Detached = true });
        Assert.False(detached.Verify().IsValid);
        Assert.False(attached.Verify(Content).IsValid);
        Assert.True(detached.Verify(Content).IsValid);
        Assert.False(detached.Verify("other"u8).IsValid);
    }

    private static string Describe(SignedDataReport r) =>
        string.Join(" | ", r.Checks.Concat(r.Signers.SelectMany(static s => s.Checks.Concat(s.Countersignatures.SelectMany(static c => c.Checks)))).Where(static c => c.Status is not (CmsCheckStatus.Passed or CmsCheckStatus.NotApplicable)).Select(static c => $"{c.Rule}:{c.Status}:{c.Reason}"));

    [Fact]
    public void DamagedSignatureAlgorithmParametersAreReportedNotThrown()
    {
        // A fuzz run found RSASSA-PSS parameters with a malformed hash identifier escaping the verifier as a different exception type.
        SignerKit k = CmsKeys.Get(SigKind.RsaPss);
        byte[] enc = SignedData.Create(Content, [k.Spec()]).Encoded.ToArray();
        SignerInfo si = SignedData.Parse(enc).Signers[0];
        int at = enc.AsSpan().LastIndexOf(si.SignatureAlgorithm.Encoded.Span);
        Assert.True(at > 0);
        for (int i = 0; i < si.SignatureAlgorithm.Encoded.Length; i++)
        {
            foreach (byte value in new byte[] { 0x00, 0xFF, 0x30, 0x06 })
            {
                byte[] bad = (byte[])enc.Clone();
                bad[at + i] = value;
                if (SignedData.TryParse(bad, out SignedData? sd) && sd is not null)
                {
                    _ = sd.Verify().IsValid; // any verdict, but no exception
                }
            }
        }
    }
}
