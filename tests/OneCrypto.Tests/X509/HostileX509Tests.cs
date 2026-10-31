using System.Security.Cryptography;
using OneCrypto.Fuzz;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.X509;

/// <summary>Hostile and damaged input for the PKI models: typed errors only, limits on, received bytes untouched.</summary>
public class HostileX509Tests
{
    private static byte[] Nest(int depth)
    {
        byte[] inner = [0x05, 0x00];
        for (int i = 0; i < depth; i++)
        {
            int n = inner.Length;
            byte[] hdr = n < 0x80 ? [0x30, (byte)n] : n < 0x100 ? [0x30, 0x81, (byte)n] : n < 0x10000 ? [0x30, 0x82, (byte)(n >> 8), (byte)n] : [0x30, 0x83, (byte)(n >> 16), (byte)(n >> 8), (byte)n];
            inner = [.. hdr, .. inner];
        }

        return inner;
    }

    [Fact]
    public void DeepNestingHugeLengthsAndEmptyInputAreTypedErrors()
    {
        foreach (byte[] bad in new[] { Nest(5000), [0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF], [0x30, 0x80, 0x30, 0x80], [], [0x30], new byte[100_000] })
        {
            Assert.False(Certificate.TryParse(bad, out _));
            Assert.False(CertificateRevocationList.TryParse(bad, out _));
            Assert.False(CertificateSigningRequest.TryParse(bad, out _));
            Assert.False(OcspRequest.TryParse(bad, out _));
            Assert.False(OcspResponse.TryParse(bad, out _));
            Assert.False(AttributeCertificate.TryParse(bad, out _));
            Assert.False(PublicKeyInfo.TryParse(bad, out _));
            Assert.False(DistinguishedName.TryParse(bad, out _));
        }
    }

    [Fact]
    public void LimitsApplyToNamesExtensionsAndSize()
    {
        using var key = new TestKey(KeyKind.EcP256);
        var rdns = new List<(string, string)>();
        for (int i = 0; i < 65; i++)
        {
            rdns.Add((KnownOids.OrganizationalUnit, "u" + i));
        }

        DistinguishedName many = DistinguishedName.Create([.. rdns]);
        Assert.Equal(X509Error.LimitExceeded, Assert.Throws<X509ParseException>(() => DistinguishedName.Parse(many.Encoded)).Error);

        Extension[] manyExt = [.. Enumerable.Range(0, 129).Select(i => Extension.Create("1.2.3." + i, false, new byte[] { 5, 0 }))];
        CertificateOptions o = new() { Subject = many.Rdns.Count > 0 ? DistinguishedName.Empty : many, NotBefore = Pki.Now, NotAfter = Pki.Now.AddDays(1), Extensions = manyExt };
        Certificate cert = null!;
        try
        {
            cert = CertificateBuilder.CreateSelfSigned(o, key.Signer);
        }
        catch (X509ParseException e)
        {
            Assert.Equal(X509Error.LimitExceeded, e.Error);
        }

        Assert.Null(cert);

        Certificate ok = Pki.Root(key);
        var tiny = new X509Limits { MaxEncodedSize = 100 };
        Assert.Equal(X509Error.LimitExceeded, Assert.Throws<X509ParseException>(() => Certificate.Parse(ok.Encoded, tiny)).Error);
    }

    [Fact]
    public void IndefiniteLengthBerIsReadAndStillVerifiesOverTheReceivedBytes()
    {
        using var key = new TestKey(KeyKind.EcP256);
        Certificate der = Pki.Root(key);
        // Same content, outer SEQUENCE re-framed with an indefinite length: legal BER, not DER.
        ReadOnlySpan<byte> body = der.Encoded.Span;
        int hdr = body[1] < 0x80 ? 2 : 2 + (body[1] & 0x7F);
        byte[] ber = [0x30, 0x80, .. body[hdr..], 0, 0];
        Certificate c = Certificate.Parse(ber);
        Assert.False(c.IsDer);
        Assert.True(c.Encoded.Span.SequenceEqual(ber));
        Assert.True(c.TbsCertificate.Span.SequenceEqual(der.TbsCertificate.Span));
        Assert.True(c.VerifySignature(key.Signer.PublicKey).IsValid);
        Assert.Equal(der.Subject.ToString(), c.Subject.ToString());
    }

    [Fact]
    public void UnknownCurveInAKeyIsReportedNotThrown()
    {
        using var key = new TestKey(KeyKind.EcP256);
        byte[] spki = key.Signer.PublicKey.Encoded.ToArray();
        int at = spki.AsSpan().IndexOf(new byte[] { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 });
        spki[at + 7] = 0x77;
        PublicKeyInfo odd = PublicKeyInfo.Parse(spki);
        Assert.Equal(KeyAlgorithm.EllipticCurve, odd.KeyAlgorithm);
        SignatureVerification v = odd.VerifySignature(AlgorithmIdentifier.Create(KnownOids.EcdsaSha256), "x"u8, new byte[] { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 });
        Assert.NotEqual(SignatureStatus.Valid, v.Status);
    }

    [Fact]
    public void AlgorithmAndAttributeFramingIsCheckedWhenParsing()
    {
        using var key = new TestKey(KeyKind.EcP256);
        Certificate c = Pki.Root(key);
        // Break the outer AlgorithmIdentifier (its inner length claims more than it holds) without changing the certificate's size.
        byte[] bad = c.Encoded.ToArray();
        int at = bad.AsSpan(bad.Length - 110).IndexOf(new byte[] { 0x30, 0x0A, 0x06, 0x08 }) + bad.Length - 110;
        Assert.True(at > bad.Length - 110);
        bad[at + 3] = 0x7F;
        Assert.False(Certificate.TryParse(bad, out _));
    }

    [Fact]
    public void EverySingleByteDamageToBuiltObjectsIsTypedOrHarmless()
    {
        using var key = new TestKey(KeyKind.EcP256);
        Certificate root = Pki.Root(key);
        var seeds = new List<byte[]>();
        foreach (byte[] s in X509Target.Seeds().Concat(OcspTarget.Seeds()))
        {
            seeds.Add(s);
        }

        Assert.NotEmpty(seeds);
        int runs = 0;
        foreach (byte[] seed in seeds.Where(s => s.Length < 2000))
        {
            for (int i = 1; i < seed.Length; i++)
            {
                foreach (byte flip in new byte[] { 0x01, 0x80, 0xFF })
                {
                    byte[] m = (byte[])seed.Clone();
                    m[i] ^= flip;
                    X509Target.Run(m);
                    OcspTarget.Run(m);
                    runs++;
                }
            }

            for (int cut = 2; cut < seed.Length; cut += 3)
            {
                X509Target.Run(seed.AsSpan(0, cut));
                OcspTarget.Run(seed.AsSpan(0, cut));
                runs++;
            }
        }

        Assert.True(runs > 1000);
        _ = root;
    }

    [Fact]
    public void CrlWithManyEntriesIsReadWithoutCopyingThem()
    {
        using var key = new TestKey(KeyKind.EcP256);
        Certificate root = Pki.Root(key);
        RevokedCertificateInfo[] entries = [.. Enumerable.Range(1, 20_000).Select(i => new RevokedCertificateInfo(i, Pki.Now, RevocationReason.Superseded))];
        CertificateRevocationList crl = RevocationListBuilder.Create(new RevocationListOptions { ThisUpdate = Pki.Now, Revoked = entries, Number = 1 }, key.Signer, root);
        Assert.Equal(20_000, crl.Entries.Count());
        Assert.NotNull(crl.Find(new byte[] { 0x4E, 0x20 }));
        Assert.Null(crl.Find(new byte[] { 0x4E, 0x21 }));
        Assert.True(crl.VerifySignature(root).IsValid);
    }

    [Fact]
    public void PolicyConstraintsWithTopBitSetNumberRoundTrips()
    {
        // A fuzz finding: 129 was re-encoded without its sign-padding zero and read back as negative.
        PolicyConstraints pc = PolicyConstraints.Parse(new byte[] { 0x30, 0x06, 0x80, 0x04, 0x00, 0x81, 0x31, 0x01 }.AsMemory());
        Assert.Equal(PolicyConstraints.Parse(pc.Encode()), pc);
        var pc2 = new PolicyConstraints(200, 255);
        Assert.Equal(pc2, PolicyConstraints.Parse(pc2.Encode()));
    }

    [Fact]
    public void DistinguishedNameTextWithNegativeOrHugeArcsIsAFormatError()
    {
        // A fuzz finding: the arc parser's OverflowException escaped.
        Assert.ThrowsAny<FormatException>(() => DistinguishedName.FromString("0.-2.-=x"));
        Assert.ThrowsAny<FormatException>(() => DistinguishedName.FromString("2.99999999999999999999999=x"));
    }
}
