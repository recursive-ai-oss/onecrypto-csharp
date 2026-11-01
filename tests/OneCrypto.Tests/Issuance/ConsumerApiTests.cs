using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Issuance;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Issuance;

public class ConsumerApiTests
{
    private static IssuanceKit Kit => IssuanceKit.Get();

    [Fact]
    public void ACrlDatedBeforeTheCaCertificateIsRefusedWithAMessageSayingWhatToDo()
    {
        CertificateAuthority ca = Kit.Intermediate;
        IssuanceException e = Assert.Throws<IssuanceException>(() => ca.IssueCrl(new CrlIssueOptions
        {
            ThisUpdate = ca.Certificate.NotBefore.AddDays(-1),
            NextUpdate = ca.Certificate.NotBefore.AddDays(6),
            Number = 1,
        }));
        Assert.Equal("issuer-validity", e.Rule);
        Assert.Contains("before the CA certificate's notBefore", e.Message, StringComparison.Ordinal);
        Assert.Contains("Set ThisUpdate", e.Message, StringComparison.Ordinal);
        Assert.Contains("5.1.2.4", e.Message, StringComparison.Ordinal);

        // At the CA certificate's notBefore the list is fine.
        CertificateRevocationList crl = ca.IssueCrl(new CrlIssueOptions { ThisUpdate = ca.Certificate.NotBefore, NextUpdate = ca.Certificate.NotBefore.AddDays(7), Number = 1 });
        Assert.Equal(ca.Certificate.NotBefore.ToUnixTimeSeconds(), crl.ThisUpdate.ToUnixTimeSeconds());
    }

    [Fact]
    public void ANameIsReadFromDerOrFromTextUnderNamesThatSayWhich()
    {
        DistinguishedName fromText = DistinguishedName.FromString("CN=Example,O=Org");
        Assert.True(DistinguishedName.Parse("CN=Example,O=Org").Matches(fromText));

        DistinguishedName fromDer = DistinguishedName.FromDer(fromText.Encoded);
        Assert.True(fromDer.Matches(fromText));
        Assert.True(DistinguishedName.TryFromDer(fromText.Encoded, out DistinguishedName? t) && t!.Matches(fromText));
        Assert.False(DistinguishedName.TryFromDer("CN=Example"u8.ToArray(), out _));
        Assert.True(DistinguishedName.TryFromString("CN=Example", out DistinguishedName? s) && s!.Rdns.Count == 1);
        Assert.False(DistinguishedName.TryFromString("not a name", out _));

        // The old DER entry point still means DER, and says so when it is given text bytes.
        Assert.Throws<X509ParseException>(() => DistinguishedName.Parse("CN=Example"u8.ToArray()));
    }
}
