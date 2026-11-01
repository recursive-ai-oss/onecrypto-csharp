using System.Text;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>
/// Finds certificates in what a Web Key Directory or keyserver returned, using the recordings the Online tests replay (a WKD answer from a domain that
/// publishes, and keys.openpgp.org's answer for a well-known key).
/// </summary>
public class KeyDiscoveryTests
{
    private const string WiktorFingerprint = "653909A2F0E37C106F5FAF546C8857E0D8E8F074";

    private static byte[] Recorded(string file, string uriContains)
    {
        string path = Path.Combine(TestFiles.TestData, "online", file + ".exchanges.json");
        var log = Online.ExchangeLog.Parse(File.ReadAllBytes(path));
        return log.Exchanges.First(e => e.Status == 200 && e.Uri.Contains(uriContains, StringComparison.Ordinal)).Body;
    }

    private static byte[] Wiktor => Recorded("vks-keys-openpgp-org", "by-fingerprint");

    private static byte[] Dkg => Recorded("wkd-dkg", "/hu/");

    [Fact]
    public void AWkdAnswerIsCutDownToTheQueriedAddress()
    {
        PgpCertificate original = PgpCertificate.Parse(Dkg);
        DiscoveredKeys d = KeyDiscovery.ForAddress(Dkg, "DKG@FifthHorseman.net");
        PgpCertificate cert = Assert.Single(d.Certificates);
        Assert.Equal(original.Fingerprint, cert.Fingerprint);
        Assert.NotEmpty(cert.UserIds);
        Assert.All(cert.UserIds, u => Assert.Contains("dkg@fifthhorseman.net", u, StringComparison.OrdinalIgnoreCase));
        Assert.All(cert.Transferable.Users, u => Assert.IsType<UserIdPacket>(u.Identity));
        Assert.Equal(original.Keys.Count, cert.Keys.Count);
        Assert.Empty(d.Dropped);
    }

    [Fact]
    public void ACertificateWithoutTheAddressIsDroppedAndSaidSo()
    {
        DiscoveredKeys d = KeyDiscovery.ForAddress(Dkg, "someone.else@fifthhorseman.net");
        Assert.Empty(d.Certificates);
        DiscoveryDrop drop = Assert.Single(d.Dropped);
        Assert.Contains("no User ID", drop.Reason, StringComparison.Ordinal);
        Assert.Equal(PgpCertificate.Parse(Dkg).Fingerprint, drop.Fingerprint);
    }

    [Fact]
    public void ThirdPartyCertificationsAreRemovedFromAnAddressLookupUnlessKept()
    {
        DiscoveredKeys stripped = KeyDiscovery.ForAddress(Wiktor, "wiktor@archlinux.org");
        PgpCertificate cert = Assert.Single(stripped.Certificates);
        Assert.Equal(WiktorFingerprint, Convert.ToHexString(cert.Fingerprint));
        Assert.Equal(["Wiktor Kwapisiewicz <wiktor@archlinux.org>"], cert.UserIds.Where(u => u.Contains("archlinux", StringComparison.Ordinal)).ToArray());
        foreach (UserComponent u in cert.Transferable.Users)
        {
            Assert.All(u.Signatures, s => Assert.True(s.IssuerFingerprint is { } f && f.Span[1..].SequenceEqual(cert.Fingerprint) || s.IssuerKeyId is { } k && k.Span.SequenceEqual(cert.Primary.KeyId)));
        }

        DiscoveredKeys kept = KeyDiscovery.ForAddress(Wiktor, "wiktor@archlinux.org", new DiscoveryOptions { KeepThirdPartyCertifications = true });
        Assert.Equal(0, kept.ThirdPartySignaturesRemoved);
        Assert.True(kept.Certificates[0].Transferable.Users.Sum(u => u.Signatures.Count) >= cert.Transferable.Users.Sum(u => u.Signatures.Count));
        Assert.Equal(kept.Certificates[0].Transferable.Users.Sum(u => u.Signatures.Count) - cert.Transferable.Users.Sum(u => u.Signatures.Count), stripped.ThirdPartySignaturesRemoved);
    }

    [Fact]
    public void ALookupByKeyKeepsOnlyCertificatesThatHoldIt()
    {
        byte[] fpr = Convert.FromHexString(WiktorFingerprint);
        Assert.Single(KeyDiscovery.ForKey(Wiktor, fpr).Certificates);
        Assert.Single(KeyDiscovery.ForKey(Wiktor, fpr.AsSpan(12)).Certificates);

        // A subkey's fingerprint finds the certificate too.
        byte[] sub = PgpCertificate.Parse(Wiktor).Keys[^1].Fingerprint;
        Assert.Single(KeyDiscovery.ForKey(Wiktor, sub).Certificates);

        byte[] other = (byte[])fpr.Clone();
        other[0] ^= 1;
        DiscoveredKeys miss = KeyDiscovery.ForKey(Wiktor, other);
        Assert.Empty(miss.Certificates);
        Assert.Single(miss.Dropped);
        Assert.Empty(KeyDiscovery.ForKey(Wiktor, new byte[7]).Certificates);
    }

    [Fact]
    public void ArmorInsideOtherTextAndSeveralBlocksAreFound()
    {
        string wiktor = Encoding.ASCII.GetString(Wiktor);
        string dkgArmor = Armor.Encode(ArmorKind.PublicKey, Dkg);
        byte[] page = Encoding.UTF8.GetBytes("<html><pre>\n" + dkgArmor + "\nbetween\n" + wiktor + "</pre></html>");
        DiscoveredKeys all = KeyDiscovery.ReadAll(page);
        Assert.Equal(2, all.Certificates.Count);
        Assert.Empty(all.Dropped);
    }

    [Fact]
    public void BinaryConcatenatedKeysAreFound()
    {
        byte[] wiktorBin = Armor.Decode(Wiktor).Data;
        DiscoveredKeys all = KeyDiscovery.ReadAll(Dkg.Concat(wiktorBin).ToArray());
        Assert.Equal(2, all.Certificates.Count);
    }

    [Fact]
    public void SecretKeysAndGarbageAreNeverAccepted()
    {
        byte[] secret = File.ReadAllBytes(TestFiles.OpenPgp("autocrypt", "setup-key.asc"));
        DiscoveredKeys s = KeyDiscovery.ReadAll(secret);
        Assert.Empty(s.Certificates);

        byte[] secretBin = Armor.Decode(secret).Data;
        DiscoveredKeys sb = KeyDiscovery.ForAddress(secretBin, "alice@autocrypt.example");
        Assert.Empty(sb.Certificates);
        Assert.Contains("secret", Assert.Single(sb.Dropped).Reason, StringComparison.Ordinal);

        foreach (byte[] junk in new[] { [], [0x00], "hello"u8.ToArray(), [0x99, 0xFF, 0xFF, 0xFF], Dkg[..50], Encoding.ASCII.GetBytes("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!!!\n-----END PGP PUBLIC KEY BLOCK-----\n") })
        {
            DiscoveredKeys d = KeyDiscovery.ForAddress(junk, "a@example.org");
            Assert.Empty(d.Certificates);
        }
    }

    [Fact]
    public void ABadBlockDoesNotHideTheGoodOnesAndTheCountIsBounded()
    {
        string good = Armor.Encode(ArmorKind.PublicKey, Dkg);
        string bad = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!!!!\n-----END PGP PUBLIC KEY BLOCK-----\n";
        DiscoveredKeys d = KeyDiscovery.ReadAll(Encoding.ASCII.GetBytes(bad + good));
        Assert.Single(d.Certificates);
        Assert.Single(d.Dropped);

        byte[] many = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat(good, 5)));
        DiscoveredKeys capped = KeyDiscovery.ReadAll(many, new DiscoveryOptions { MaxCertificates = 2 });
        Assert.Equal(2, capped.Certificates.Count);
        Assert.Equal(3, capped.Dropped.Count);
    }

    [Theory]
    [InlineData("not an address")]
    [InlineData("")]
    [InlineData("@x")]
    public void AnInvalidQueryAddressFindsNothing(string address)
    {
        Assert.Empty(KeyDiscovery.ForAddress(Dkg, address).Certificates);
    }
}
