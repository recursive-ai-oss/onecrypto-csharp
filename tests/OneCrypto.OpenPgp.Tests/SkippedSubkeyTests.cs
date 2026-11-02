using RecursiveAI.OneCrypto.OpenPgp;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using Xunit;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>
/// A subkey that cannot be used must not cost the whole certificate (RFC 9580 §10.1). The shape comes from a published key that carries a LibrePGP
/// version 5 Kyber subkey whose key material is empty: the packet is well formed up to the material, which is missing.
/// </summary>
public sealed class SkippedSubkeyTests
{
    // Public Subkey, version 5, creation time 0, algorithm 8 (LibrePGP Kyber), four-octet material count 0.
    private static readonly byte[] EmptyKyberSubkey = [0xCE, 10, 5, 0, 0, 0, 0, 8, 0, 0, 0, 0];

    // Public Subkey with a key version no one defines.
    private static readonly byte[] FutureVersionSubkey = [0xCE, 6, 9, 0, 0, 0, 0, 22];

    private static PgpCertificate Original() => Pgp.GenerateKey("Skip <skip@example.org>", PgpKeyProfile.Rfc4880Curve25519, null, new FixedClock(new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero))).ToPublicCertificate();

    // Primary, user ID and its signatures, then the bad subkey with a signature after it, then the usable subkey.
    private static byte[] WithBadSubkeyInTheMiddle(PgpCertificate good, byte[] badSubkey)
    {
        TransferableKey t = good.Transferable;
        int at = t.Packets.ToList().FindIndex(p => p.Tag == PacketTag.PublicSubkey || p.Tag == PacketTag.SecretSubkey);
        Packet bad = Assert.Single(PacketParser.ParseAll(badSubkey));
        var list = new List<Packet>(t.Packets);
        list.Insert(at, bad);
        list.Insert(at + 1, t.Subkeys[0].Signatures[0]);
        using var ms = new MemoryStream();
        PacketParser.Write(list, ms);
        return ms.ToArray();
    }

    [Fact]
    public void ABrokenSubkeyIsSkippedAndTheRestOfTheCertificateStays()
    {
        PgpCertificate good = Original();
        byte[] bytes = WithBadSubkeyInTheMiddle(good, EmptyKyberSubkey);

        PgpCertificate cert = PgpCertificate.Parse(bytes);

        Assert.Equal(good.Fingerprint, cert.Fingerprint);
        Assert.Equal(good.Keys.Count, cert.Keys.Count);
        SkippedSubkeyComponent skipped = Assert.Single(cert.SkippedSubkeys);
        Assert.Single(skipped.Signatures);
        Assert.Equal(5, skipped.Version);
        Assert.NotNull(skipped.Packet.DecodeFailure);
        Assert.False(string.IsNullOrWhiteSpace(skipped.Reason));
        Assert.Empty(good.SkippedSubkeys);
    }

    [Fact]
    public void ASkippedSubkeyWritesBackByteForByte()
    {
        byte[] bytes = WithBadSubkeyInTheMiddle(Original(), EmptyKyberSubkey);
        PgpCertificate cert = PgpCertificate.Parse(bytes);
        Assert.Equal(bytes, cert.ExportPublic());
        Assert.Equal(bytes, cert.Export());
    }

    [Fact]
    public void AnUnknownKeyVersionIsSkippedWithItsReason()
    {
        PgpCertificate cert = PgpCertificate.Parse(WithBadSubkeyInTheMiddle(Original(), FutureVersionSubkey));
        SkippedSubkeyComponent skipped = Assert.Single(cert.SkippedSubkeys);
        Assert.Null(skipped.Packet.DecodeFailure);
        Assert.Contains("version 9", skipped.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ADiscoveredCertificateKeepsItsUsableKeysAndItsSkippedOne()
    {
        PgpCertificate good = Original();
        byte[] bytes = WithBadSubkeyInTheMiddle(good, EmptyKyberSubkey);

        DiscoveredKeys found = KeyDiscovery.ForAddress(bytes, "skip@example.org");

        PgpCertificate cert = Assert.Single(found.Certificates);
        Assert.Empty(found.Dropped);
        Assert.Equal(good.Keys.Count, cert.Keys.Count);
        Assert.Single(cert.SkippedSubkeys);
    }

    [Fact]
    public void ABrokenPrimaryKeyStillFailsWithATypedError()
    {
        PgpCertificate good = Original();
        byte[] brokenPrimary = [0xC6, 10, 5, 0, 0, 0, 0, 8, 0, 0, 0, 0];
        byte[] rest = good.ExportPublic().AsSpan(good.Transferable.Primary.OriginalEncoding.Length).ToArray();
        byte[] bytes = [.. brokenPrimary, .. rest];

        Assert.Throws<OpenPgpParseException>(() => PgpCertificate.Parse(bytes));
        Assert.Throws<OpenPgpParseException>(() => PgpCertificate.ParseAll(bytes));
    }

    [Fact]
    public void ASkippedSecretSubkeyIsLeftOutOfThePublicForm()
    {
        PgpCertificate secret = Pgp.GenerateKey("Skip <skip@example.org>", PgpKeyProfile.Rfc4880Curve25519, null, new FixedClock(new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero)));
        Assert.True(secret.HasSecretKeyMaterial);
        TransferableKey t = secret.Transferable;
        int at = t.Packets.ToList().FindIndex(p => p.Tag == PacketTag.SecretSubkey);
        // Secret Subkey, version 5, algorithm 8, empty public material.
        Packet bad = Assert.Single(PacketParser.ParseAll(new byte[] { 0xC7, 10, 5, 0, 0, 0, 0, 8, 0, 0, 0, 0 }));
        var list = new List<Packet>(t.Packets);
        list.Insert(at, bad);
        list.Insert(at + 1, t.Subkeys[0].Signatures[0]);
        using var ms = new MemoryStream();
        PacketParser.Write(list, ms);

        PgpCertificate cert = PgpCertificate.Parse(ms.ToArray());

        Assert.True(cert.HasSecretKeyMaterial);
        Assert.Single(cert.SkippedSubkeys);
        PgpCertificate pub = PgpCertificate.Parse(cert.ExportPublic());
        Assert.False(pub.HasSecretKeyMaterial);
        Assert.Empty(pub.SkippedSubkeys);
        Assert.Equal(secret.Keys.Count, pub.Keys.Count);
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
