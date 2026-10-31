using System.Numerics;
using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.X509;

public class ExtensionTests
{
    private static void RoundTrip<T>(T value)
        where T : class, IExtensionValue<T>
    {
        byte[] der = value.Encode();
        T parsed = T.Parse(der);
        Assert.True(parsed.Encode().AsSpan().SequenceEqual(der), typeof(T).Name);

        Extension e = Extension.Create(value, critical: true);
        Assert.Equal(T.ExtensionOid, e.Oid);
        Assert.True(e.Critical);
        Assert.True(e.Value.Span.SequenceEqual(der));
        var list = ExtensionCollection.Create([e]);
        Assert.NotNull(list.Get<T>());
    }

    [Fact]
    public void EveryStandardExtensionRoundTrips()
    {
        GeneralName dns = GeneralName.Dns("example.test");
        GeneralName dir = GeneralName.FromDirectoryName(DistinguishedName.Create((KnownOids.Country, "DE"), (KnownOids.CommonName, "Dir")));
        RoundTrip(new BasicConstraints(true, 3));
        RoundTrip(new BasicConstraints(false));
        RoundTrip(new KeyUsageExtension(KeyUsages.DigitalSignature | KeyUsages.KeyCertSign | KeyUsages.DecipherOnly));
        RoundTrip(new KeyUsageExtension(KeyUsages.None));
        RoundTrip(new ExtendedKeyUsage([KnownOids.ServerAuth, KnownOids.OcspSigning]));
        RoundTrip(new SubjectKeyIdentifier(new byte[] { 1, 2, 3 }));
        RoundTrip(new AuthorityKeyIdentifier(new byte[] { 9, 9 }, [dir], new byte[] { 0x01, 0x00 }));
        RoundTrip(new SubjectAlternativeName([dns, GeneralName.Email("a@b.test"), GeneralName.FromUri("https://x.test/"), GeneralName.FromIPAddress(new byte[16]), dir, GeneralName.FromRegisteredId("1.2.3.4"), GeneralName.Other("1.3.6.1.4.1.311.20.2.3", new byte[] { 0x0C, 1, (byte)'u' })]));
        RoundTrip(new IssuerAlternativeName([dns]));
        RoundTrip(new NameConstraints([new GeneralSubtree(dns)], [new GeneralSubtree(GeneralName.FromIPAddress(new byte[] { 10, 0, 0, 0, 255, 0, 0, 0 }), 0, null)]));
        RoundTrip(new CertificatePolicies([new PolicyInformation(KnownOids.AnyPolicy, []), new PolicyInformation("1.2.3", [new PolicyQualifier("1.3.6.1.5.5.7.2.1", new byte[] { 0x16, 2, (byte)'h', (byte)'i' })])]));
        RoundTrip(new PolicyMappings([new PolicyMapping("1.2.3", "1.2.4")]));
        RoundTrip(new PolicyConstraints(0, 2));
        RoundTrip(new PolicyConstraints(null, 1));
        RoundTrip(new InhibitAnyPolicy(4));
        RoundTrip(new CrlDistributionPoints([new DistributionPoint(new DistributionPointName([GeneralName.FromUri("http://crl.test/a.crl")]), RevocationReasons.KeyCompromise | RevocationReasons.Superseded, [dir])]));
        RoundTrip(new FreshestCrl([new DistributionPoint(new DistributionPointName([GeneralName.FromUri("http://crl.test/d.crl")]))]));
        RoundTrip(new AuthorityInfoAccess([new AccessDescription(KnownOids.AdOcsp, GeneralName.FromUri("http://ocsp.test")), new AccessDescription(KnownOids.AdCaIssuers, GeneralName.FromUri("http://ca.test/ca.der"))]));
        RoundTrip(new SubjectInfoAccess([new AccessDescription("1.3.6.1.5.5.7.48.5", GeneralName.FromUri("http://repo.test/"))]));
        RoundTrip(new CrlNumber(BigInteger.Pow(2, 100)));
        RoundTrip(new DeltaCrlIndicator(7));
        RoundTrip(new IssuingDistributionPoint(new DistributionPointName([dns]), OnlyContainsUserCerts: true, OnlySomeReasons: RevocationReasons.CACompromise, IndirectCrl: true));
        RoundTrip(new CrlReasonExtension(RevocationReason.KeyCompromise));
        RoundTrip(new InvalidityDate(new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero)));
        RoundTrip(new CertificateIssuerExtension([dir]));
        RoundTrip(new OcspNonce(new byte[] { 1, 2, 3, 4 }));
        RoundTrip(new OcspNoCheck());
    }

    [Fact]
    public void DecodedValuesCarryTheirFields()
    {
        var aki = AuthorityKeyIdentifier.Parse(new AuthorityKeyIdentifier(new byte[] { 7 }, null, new byte[] { 5 }).Encode());
        Assert.Equal(new byte[] { 7 }, aki.KeyIdentifier.ToArray());
        Assert.Equal(new byte[] { 5 }, aki.AuthorityCertSerialNumber.ToArray());
        Assert.Null(aki.AuthorityCertIssuer);

        var nc = NameConstraints.Parse(new NameConstraints([new GeneralSubtree(GeneralName.Dns("a.test"), 0, null)], null).Encode());
        Assert.Equal("DNS:a.test", nc.PermittedSubtrees![0].Base.ToString());
        Assert.Null(nc.ExcludedSubtrees);

        var dp = CrlDistributionPoints.Parse(new CrlDistributionPoints([new DistributionPoint(new DistributionPointName([GeneralName.FromUri("http://x/")]), RevocationReasons.Superseded)]).Encode());
        Assert.Equal("URI:http://x/", dp.Points[0].Name!.FullName![0].ToString());
        Assert.Equal(RevocationReasons.Superseded, dp.Points[0].Reasons);

        Assert.Equal(["http://ocsp.test"], AuthorityInfoAccess.Parse(new AuthorityInfoAccess([new AccessDescription(KnownOids.AdOcsp, GeneralName.FromUri("http://ocsp.test"))]).Encode()).UrisFor(KnownOids.AdOcsp));
    }

    [Fact]
    public void NonceReadsBothRfcAndRawForms()
    {
        Assert.Equal(new byte[] { 1, 2, 3 }, OcspNonce.Parse(new byte[] { 4, 3, 1, 2, 3 }).Nonce.ToArray());
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6 }, OcspNonce.Parse(new byte[] { 1, 2, 3, 4, 5, 6 }).Nonce.ToArray());
    }

    [Fact]
    public void MalformedExtensionsAreTypedErrors()
    {
        Assert.Throws<X509ParseException>(() => BasicConstraints.Parse(new byte[] { 0x30, 0x03, 0x02, 0x01, 0xFF }));
        Assert.Throws<X509ParseException>(() => KeyUsageExtension.Parse(new byte[] { 0x04, 0x00 }));
        Assert.Throws<X509ParseException>(() => SubjectAlternativeName.Parse(new byte[] { 0x30, 0x02, 0x89, 0x00 }));
        Assert.Throws<X509ParseException>(() => SubjectAlternativeName.Parse(new byte[] { 0x30, 0x03, 0x87, 0x01, 0x01 }));
        Assert.Throws<X509ParseException>(() => CrlReasonExtension.Parse(new byte[] { 0x0A, 0x01, 0x07 }));
        Assert.False(ExtensionCollection.Create([Extension.Create(KnownOids.BasicConstraints, true, new byte[] { 1 })]).TryGet(out BasicConstraints? bc));
        Assert.Null(bc);
    }

    [Fact]
    public void UnknownExtensionsAreKeptWithCriticality()
    {
        using var key = new TestKey(KeyKind.EcP256);
        Certificate c = CertificateBuilder.CreateSelfSigned(
            new CertificateOptions
            {
                Subject = DistinguishedName.Create((KnownOids.CommonName, "x")),
                NotBefore = Pki.Now,
                NotAfter = Pki.Now.AddDays(1),
                Extensions = [Extension.Create("1.2.3.4.5", true, new byte[] { 0x05, 0x00 })],
            },
            key.Signer);
        Extension e = c.Extensions.Find("1.2.3.4.5")!;
        Assert.True(e.Critical);
        Assert.Equal(new byte[] { 5, 0 }, e.Value.ToArray());
    }
}
