using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.X509;

public class CertificateTests
{
    public static IEnumerable<object[]> Kinds() => Enum.GetValues<KeyKind>().Where(TestKey.IsAvailable).Select(k => new object[] { k });

    [Theory]
    [MemberData(nameof(Kinds))]
    public void BuiltChainParsesRoundTripsAndVerifies(KeyKind kind)
    {
        using var rootKey = new TestKey(kind);
        using var leafKey = new TestKey(KeyKind.EcP256);
        Certificate root = Pki.Root(rootKey);
        Certificate leaf = Pki.Leaf(leafKey, root, rootKey);

        Assert.True(root.IsSelfSigned);
        Assert.True(leaf.VerifySignature(root).IsValid, leaf.VerifySignature(root).Reason);
        using var other = new TestKey(kind);
        Assert.Equal(SignatureStatus.Invalid, leaf.VerifySignature(Pki.Root(other)).Status);

        // Re-reading the encoding gives the same object content; nothing is rewritten.
        Certificate again = Certificate.Parse(leaf.Encoded.ToArray());
        Assert.True(again.Encoded.Span.SequenceEqual(leaf.Encoded.Span));
        Assert.True(again.IsDer);
        Assert.Equal(3, again.Version);
        Assert.Equal("CN=leaf.example.test", again.Subject.ToString());
        Assert.Equal("CN=Test Root CA,O=OneCrypto Tests", again.Issuer.ToString());
        Assert.True(again.Issuer.Matches(root.Subject));
        Assert.Equal(root.SubjectKeyIdentifier!.KeyIdentifier.ToArray(), again.AuthorityKeyIdentifier!.KeyIdentifier.ToArray());
        Assert.False(again.BasicConstraints!.IsCA);
        Assert.Equal(KeyUsages.DigitalSignature, again.KeyUsage!.Usages);
        Assert.Equal([KnownOids.ServerAuth, KnownOids.ClientAuth], again.ExtendedKeyUsage!.Purposes);
        IReadOnlyList<GeneralName> san = again.SubjectAlternativeName!.Names;
        Assert.Equal(["DNS:leaf.example.test", "email:ops@example.test", "IP:192.0.2.7"], san.Select(n => n.ToString()));
        Assert.Equal(KeyAlgorithm.EllipticCurve, again.PublicKey.KeyAlgorithm);
        Assert.Equal(KnownOids.P256, again.PublicKey.CurveOid);
        Assert.Equal(256, again.PublicKey.KeySizeBits);
    }

    [Fact]
    public void PlatformCertificateAgreesWithOurFields()
    {
        using var rootKey = new TestKey(KeyKind.Rsa2048);
        using var leafKey = new TestKey(KeyKind.EcP256);
        Certificate leaf = Pki.Leaf(leafKey, Pki.Root(rootKey), rootKey);
        using X509Certificate2 bcl = leaf.ToX509Certificate2();

        Assert.Equal(bcl.SubjectName.RawData, leaf.Subject.Encoded.ToArray());
        Assert.Equal(bcl.IssuerName.RawData, leaf.Issuer.Encoded.ToArray());
        Assert.Equal(bcl.GetSerialNumber().Reverse().ToArray(), leaf.SerialNumber.ToArray().SkipWhile(b => b == 0).ToArray());
        Assert.Equal(bcl.NotBefore.ToUniversalTime(), leaf.NotBefore.UtcDateTime);
        Assert.Equal(bcl.NotAfter.ToUniversalTime(), leaf.NotAfter.UtcDateTime);
        Assert.Equal(bcl.Extensions.Select(e => e.Oid!.Value).ToArray(), leaf.Extensions.Select(e => e.Oid).ToArray());
        Assert.Equal(bcl.PublicKey.EncodedKeyValue.RawData, leaf.PublicKey.KeyBits.ToArray());
        Assert.Equal(bcl.PublicKey.Oid.Value, leaf.PublicKey.Algorithm.Oid);

        Certificate back = Certificate.FromX509Certificate2(bcl);
        Assert.Equal(leaf, back);
    }

    [Fact]
    public void SignatureOverReceivedBytesDetectsChange()
    {
        using var rootKey = new TestKey(KeyKind.EcP256);
        Certificate root = Pki.Root(rootKey);
        byte[] bad = root.Encoded.ToArray();
        // Flip a bit inside the subject common name: the structure still parses, the signature must not verify.
        int at = bad.AsSpan().IndexOf("Test Root CA"u8);
        bad[at] ^= 1;
        Certificate tampered = Certificate.Parse(bad);
        Assert.Equal(SignatureStatus.Invalid, tampered.VerifySignature(rootKey.Signer.PublicKey).Status);
    }

    [Fact]
    public void NameStringsRoundTripAndEscape()
    {
        var dn = DistinguishedName.FromString("""CN=Jane \"Q\" Doe\, Jr.,OU=a\+b,O=Acme #1,C=US""");
        Assert.Equal("""CN=Jane \"Q\" Doe\, Jr.,OU=a\+b,O=Acme #1,C=US""", dn.ToString());
        Assert.Equal("C=US", dn.Rdns[0].ToString());
        Assert.True(dn.Matches(DistinguishedName.FromString("""cn=jane \"q\"  doe\, jr.,ou=A\+B,o=ACME #1,c=us""")));
        Assert.False(dn.Matches(DistinguishedName.Empty));
        Assert.Equal(string.Empty, DistinguishedName.Empty.ToString());
    }

    [Fact]
    public void MalformedInputRaisesTypedErrors()
    {
        Assert.False(Certificate.TryParse(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 }, out _));
        Assert.Throws<X509ParseException>(() => Certificate.Parse(new byte[] { 0x30, 0x80 }));
        Assert.Throws<X509ParseException>(() => Certificate.Parse(Array.Empty<byte>()));
        using var k = new TestKey(KeyKind.EcP256);
        byte[] der = Pki.Root(k).Encoded.ToArray();
        Assert.Throws<X509ParseException>(() => Certificate.Parse([.. der, 0]));
        for (int cut = 0; cut < der.Length; cut += 7)
        {
            Assert.False(Certificate.TryParse(der.AsMemory(0, cut), out _));
        }
    }

    [Fact]
    public void OpenSslReadsAndVerifiesTheChainWeBuild()
    {
        OpenSslTool.RequireOrSkip();
        string dir = OpenSslTool.TempDir("chain");
        foreach (KeyKind kind in Enum.GetValues<KeyKind>().Where(TestKey.IsAvailable))
        {
            if (kind == KeyKind.MlDsa65 && !OpenSslTool.Has("ML-DSA-65"))
            {
                continue;
            }

            using var rootKey = new TestKey(kind);
            using var leafKey = new TestKey(KeyKind.EcP256);
            Certificate root = Pki.Root(rootKey);
            Certificate leaf = Pki.Leaf(leafKey, root, rootKey);
            File.WriteAllText(Path.Combine(dir, $"{kind}-root.pem"), root.ToPem());
            File.WriteAllText(Path.Combine(dir, $"{kind}-leaf.pem"), leaf.ToPem());
            foreach (string n in new[] { "root", "leaf" })
            {
                (int code, string text) = OpenSslTool.Run("x509", "-in", Path.Combine(dir, $"{kind}-{n}.pem"), "-noout", "-text");
                Assert.True(code == 0, $"{kind} {n}: {text}");
            }

            (int vcode, string vout) = OpenSslTool.Run("verify", "-attime", Pki.Now.ToUnixTimeSeconds().ToString(), "-CAfile", Path.Combine(dir, $"{kind}-root.pem"), Path.Combine(dir, $"{kind}-leaf.pem"));
            Assert.True(vcode == 0, $"{kind}: {vout}");
        }
    }
}
