using System.Text;
using RecursiveAI.OneCrypto.OpenPgp.GnuPG;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>The committed GnuPG homes (testdata/gnupg): one directory per GnuPG version, produced by tools/oracles/gnupg-home.sh.</summary>
internal static class GnuPGHomes
{
    public static string Root { get; } = Path.Combine(TestFiles.TestData, "gnupg");

    public static IEnumerable<string> Versions => Directory.GetDirectories(Root).Select(Path.GetFileName).Where(n => n is not null).Select(n => n!).OrderBy(n => n, StringComparer.Ordinal);

    public static IEnumerable<object[]> VersionData => Versions.Select(v => new object[] { v });

    public static string Dir(string version, params string[] parts) => Path.Combine([Root, version, .. parts]);

    /// <summary>What <c>gpg --with-colons --list-keys</c> reported for a home: primary and subkey fingerprints and user IDs per key.</summary>
    public sealed record ColonKey(string Fingerprint, List<string> SubkeyFingerprints, List<string> UserIds);

    public static List<ColonKey> ReadColons(string path)
    {
        var keys = new List<ColonKey>();
        ColonKey? cur = null;
        string? last = null;
        foreach (string line in File.ReadAllLines(path))
        {
            string[] f = line.Split(':');
            switch (f[0])
            {
                case "pub":
                    cur = new ColonKey(string.Empty, [], []);
                    keys.Add(cur);
                    last = "pub";
                    break;
                case "sub":
                    last = "sub";
                    break;
                case "fpr" when cur is not null && last is not null:
                    if (last == "pub")
                    {
                        keys[^1] = cur = cur with { Fingerprint = f[9] };
                    }
                    else
                    {
                        cur.SubkeyFingerprints.Add(f[9]);
                    }

                    last = null;
                    break;
                case "uid" when cur is not null:
                    cur.UserIds.Add(Unescape(f[9]));
                    break;
            }
        }

        return keys;
    }

    private static string Unescape(string s)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '\\' && i + 3 < s.Length && s[i + 1] == 'x')
            {
                sb.Append((char)Convert.ToByte(s.Substring(i + 2, 2), 16));
                i += 3;
            }
            else
            {
                sb.Append(s[i]);
            }
        }

        return Encoding.UTF8.GetString(Encoding.Latin1.GetBytes(sb.ToString()));
    }
}

public class KeyboxTests
{
    public static IEnumerable<object[]> Homes()
    {
        foreach (string v in GnuPGHomes.Versions)
        {
            foreach (string h in new[] { "main", "many", "special" })
            {
                if (File.Exists(GnuPGHomes.Dir(v, h, "pubring.kbx")))
                {
                    yield return new object[] { v, h };
                }
            }
        }
    }

    [Theory]
    [MemberData(nameof(Homes))]
    public void FingerprintsAndUserIdsMatchGpgColonsListing(string version, string home)
    {
        byte[] data = File.ReadAllBytes(GnuPGHomes.Dir(version, home, "pubring.kbx"));
        var kbx = Keybox.Parse(data);
        Assert.NotNull(kbx.Header);
        Assert.True(kbx.Header!.ContainsOpenPgp);

        var expected = GnuPGHomes.ReadColons(GnuPGHomes.Dir(version, home, "list-keys.colons"));
        var blobs = kbx.OpenPgpBlobs.ToList();
        Assert.Equal(expected.Count, blobs.Count);
        foreach (var blob in blobs)
        {
            Assert.True(blob.ChecksumValid);
            string primary = Convert.ToHexString(blob.PrimaryFingerprint.Span);
            GnuPGHomes.ColonKey e = expected.Single(k => primary.StartsWith(k.Fingerprint, StringComparison.Ordinal) || k.Fingerprint.StartsWith(primary, StringComparison.Ordinal));

            // The index in the blob and the packets agree with each other and with what gpg prints.
            TransferableKey key = blob.ReadKey();
            Assert.Equal(key.Primary.FingerprintHex, primary);
            Assert.Equal(e.SubkeyFingerprints.Count, blob.Keys.Count - 1);
            for (int i = 0; i < e.SubkeyFingerprints.Count; i++)
            {
                string sub = blob.Keys[i + 1].FingerprintHex;
                Assert.True(sub.StartsWith(e.SubkeyFingerprints[i], StringComparison.Ordinal) || e.SubkeyFingerprints[i].StartsWith(sub, StringComparison.Ordinal));
                Assert.Equal(key.Subkeys[i].Key.FingerprintHex, sub);
            }

            Assert.Equal(e.UserIds, blob.Names.Select(n => n.Text).ToList());
            Assert.Equal(e.UserIds, key.Users.Select(u => ((UserIdPacket)u.Identity).Text).ToList());
            if (blob.Version == 1)
            {
                Assert.Equal(key.Primary.GetKeyId(), blob.Keys[0].KeyId.ToArray());
            }
        }

        // Writing the blobs back reproduces the file.
        using var ms = new MemoryStream();
        kbx.Write(ms);
        Assert.Equal(data, ms.ToArray());
    }

    [Theory]
    [MemberData(nameof(Homes))]
    public void BlobFieldsAreAsKbxutilReports(string version, string home)
    {
        // kbxutil's text dump is committed beside each keybox; compare the fields it prints.
        string dump = File.ReadAllText(GnuPGHomes.Dir(version, home, "kbxutil.txt"));
        var kbx = Keybox.Parse(File.ReadAllBytes(GnuPGHomes.Dir(version, home, "pubring.kbx")));
        string[] records = dump.Split("BEGIN-RECORD:", StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(kbx.Blobs.Count, records.Length);
        for (int i = 0; i < records.Length; i++)
        {
            Dictionary<string, string> f = records[i].Split('\n').Select(l => l.Split(": ", 2)).Where(p => p.Length == 2).GroupBy(p => p[0].Trim()).ToDictionary(g => g.Key, g => g.First()[1].Trim());
            KeyboxBlob b = kbx.Blobs[i];
            Assert.Equal(int.Parse(f["Length"]), b.Length);
            if (b is KeyboxKeyBlob k)
            {
                Assert.Equal(int.Parse(f["Data-Offset"]), k.DataOffset);
                Assert.Equal(int.Parse(f["Data-Length"]), k.DataLength);
                Assert.Equal(int.Parse(f["Key-Count"]), k.Keys.Count);
                Assert.Equal(f["Created-At"], k.CreatedAtSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture));
                Assert.Equal(f["Ownertrust"], k.OwnerTrust.ToString(System.Globalization.CultureInfo.InvariantCulture));
                Assert.Equal(f["All-Validity"], k.AllValidity.ToString(System.Globalization.CultureInfo.InvariantCulture));
                Assert.Equal(f["Checksum"].Split(' ')[0], Convert.ToHexString(k.Checksum.Span).ToLowerInvariant());
                Assert.Equal(f["Checksum"].EndsWith("[valid]", StringComparison.Ordinal), k.ChecksumValid);
                if (b is KeyboxX509Blob x)
                {
                    Assert.Equal(f["Serial-No"], Convert.ToHexString(x.SerialNumber.Span));
                    Assert.Equal(f["Subject"].Trim('"'), x.Subject);
                    Assert.Equal(f["Issuer"].Trim('"'), x.Issuer);
                }
            }
        }
    }

    [Fact]
    public void X509BlobIsPresentAndItsCertificateIsDer()
    {
        foreach (string v in GnuPGHomes.Versions)
        {
            var kbx = Keybox.Parse(File.ReadAllBytes(GnuPGHomes.Dir(v, "special", "pubring.kbx")));
            KeyboxX509Blob x = Assert.Single(kbx.X509Blobs);
            Assert.Equal(0x30, x.Certificate.Span[0]);
            Assert.Equal("O=Test,CN=onecrypto x509 test", x.Subject);
            Assert.Single(x.Keys);
            Assert.Equal(20, x.Keys[0].Fingerprint.Length);
        }
    }

    [Fact]
    public void GnuPG25WritesVersion2BlobsForVersion5Keys()
    {
        var kbx = Keybox.Parse(File.ReadAllBytes(GnuPGHomes.Dir("2.5.24", "special", "pubring.kbx")));
        KeyboxOpenPgpBlob blob = kbx.OpenPgpBlobs.Single();
        Assert.Equal(2, blob.Version);
        Assert.Equal(2, blob.Keys.Count);
        Assert.Equal(20, blob.Keys[0].Fingerprint.Length);
        Assert.Equal(32, blob.Keys[1].Fingerprint.Length);
        Assert.Equal(0x0080, blob.Keys[1].Flags);
        TransferableKey key = blob.ReadKey();
        Assert.Equal(5, key.Subkeys[0].Key.Version);
        Assert.Equal(key.Subkeys[0].Key.FingerprintHex, blob.Keys[1].FingerprintHex);
    }

    [Fact]
    public void HeaderFieldsAreRead()
    {
        var kbx = Keybox.Parse(File.ReadAllBytes(GnuPGHomes.Dir("2.4.8", "main", "pubring.kbx")));
        Assert.Equal(1, kbx.Header!.Version);
        Assert.True(kbx.Header.CreatedAtSeconds > 1_700_000_000);
    }

    [Fact]
    public void DamageIsATypedError()
    {
        byte[] good = File.ReadAllBytes(GnuPGHomes.Dir("2.4.8", "main", "pubring.kbx"));
        Assert.False(Keybox.TryParse(good.AsMemory(0, good.Length - 3), out _, out GnuPGFailure f1));
        Assert.Equal(GnuPGError.Truncated, f1.Error);

        byte[] badMagic = (byte[])good.Clone();
        badMagic[8] ^= 1;
        Assert.False(Keybox.TryParse(badMagic, out _, out GnuPGFailure f2));
        Assert.Equal(GnuPGError.BadHeader, f2.Error);

        Assert.Throws<GnuPGFormatException>(() => Keybox.Parse(ReadOnlyMemory<byte>.Empty));

        // A key blob whose data offset points past the blob.
        byte[] bad = (byte[])good.Clone();
        int blob1 = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bad);
        bad[blob1 + 8] = 0x7f;
        Assert.False(Keybox.TryParse(bad, out _, out GnuPGFailure f3));
        Assert.Equal(GnuPGError.OutOfBounds, f3.Error);

        // A flipped bit in the packets is reported by the checksum, not hidden.
        byte[] flipped = (byte[])good.Clone();
        flipped[blob1 + 200] ^= 0x10;
        var kbx = Keybox.Parse(flipped);
        Assert.False(kbx.OpenPgpBlobs.First().ChecksumValid);
    }

    [Fact]
    public void EveryTruncationAndByteFlipEndsInATypedResult()
    {
        byte[] good = File.ReadAllBytes(GnuPGHomes.Dir("2.5.24", "special", "pubring.kbx"));
        for (int len = 0; len < good.Length; len += 7)
        {
            _ = Keybox.TryParse(good.AsMemory(0, len), out _, out _);
        }

        for (int i = 0; i < good.Length; i++)
        {
            byte[] m = (byte[])good.Clone();
            m[i] ^= 0xA5;
            if (Keybox.TryParse(m, out Keybox? k, out _))
            {
                foreach (KeyboxOpenPgpBlob b in k!.OpenPgpBlobs)
                {
                    try
                    {
                        b.ReadKey();
                    }
                    catch (Exception e) when (e is OpenPgpParseException or GnuPGFormatException)
                    {
                    }
                }
            }
        }
    }
}

public class LegacyKeyringTests
{
    [Theory]
    [MemberData(nameof(GnuPGHomes.VersionData), MemberType = typeof(GnuPGHomes))]
    public void ExportAndLegacyRingRoundTripByteForByte(string version)
    {
        foreach (string rel in new[] { "legacy/export.pgp", "legacy/pubring.gpg", "main/export.pgp", "many/export.pgp" })
        {
            string path = GnuPGHomes.Dir(version, rel.Split('/')[0], rel.Split('/')[1]);
            byte[] data = File.ReadAllBytes(path);
            IReadOnlyList<TransferableKey> keys = LegacyKeyring.Read(data);
            using var ms = new MemoryStream();
            LegacyKeyring.Write(keys, ms);
            Assert.Equal(data, ms.ToArray());
        }
    }

    [Theory]
    [MemberData(nameof(GnuPGHomes.VersionData), MemberType = typeof(GnuPGHomes))]
    public void LegacyRingHoldsTheSameKeysAsTheColonsListingAndKeepsRingTrust(string version)
    {
        var keys = LegacyKeyring.Read(File.ReadAllBytes(GnuPGHomes.Dir(version, "legacy", "pubring.gpg")));
        var expected = GnuPGHomes.ReadColons(GnuPGHomes.Dir(version, "legacy", "list-keys.colons"));
        Assert.Equal(expected.Select(e => e.Fingerprint).Order().ToList(), keys.Select(k => k.Primary.FingerprintHex).Order().ToList());

        var trust = keys.SelectMany(k => k.Packets).OfType<TrustPacket>().ToList();
        Assert.NotEmpty(trust);
        foreach (TrustPacket t in trust)
        {
            Assert.True(RingTrust.TryDecode(t, out RingTrust? rt), "trust packet body " + Convert.ToHexString(t.Body.Span));
            Assert.NotNull(rt);
        }

        Assert.Contains(trust, t => RingTrust.TryDecode(t, out RingTrust? r) && r!.Kind == RingTrustKind.KeySource);
        Assert.Contains(trust, t => RingTrust.TryDecode(t, out RingTrust? r) && r!.Kind == RingTrustKind.Signature);
    }

    [Fact]
    public void GarbageIsATypedError()
    {
        Assert.False(LegacyKeyring.TryRead(new byte[] { 1, 2, 3, 4, 5 }, out _, out _));
    }
}

public class TrustDbTests
{
    [Theory]
    [MemberData(nameof(GnuPGHomes.VersionData), MemberType = typeof(GnuPGHomes))]
    public void OwnerTrustEqualsGpgExportOwnertrust(string version)
    {
        foreach (string home in new[] { "main", "many", "special" })
        {
            var db = TrustDb.Parse(File.ReadAllBytes(GnuPGHomes.Dir(version, home, "trustdb.gpg")));
            var expected = OwnerTrustExport.Parse(File.ReadAllText(GnuPGHomes.Dir(version, home, "ownertrust.txt")));
            var actual = db.OwnerTrust.Select(e => (e.FingerprintHex, e.Value)).OrderBy(x => x.FingerprintHex, StringComparer.Ordinal).ToList();
            Assert.Equal(expected.Select(e => (e.FingerprintHex, e.Value)).OrderBy(x => x.FingerprintHex, StringComparer.Ordinal).ToList(), actual);
            Assert.Equal(3, db.Version);
        }
    }

    [Fact]
    public void LevelsAreNamed()
    {
        var db = TrustDb.Parse(File.ReadAllBytes(GnuPGHomes.Dir("2.4.8", "main", "trustdb.gpg")));
        string[] lines = File.ReadAllLines(GnuPGHomes.Dir("2.4.8", "main", "list-keys.colons")).Where(l => l.StartsWith("pub:", StringComparison.Ordinal)).ToArray();
        var colons = GnuPGHomes.ReadColons(GnuPGHomes.Dir("2.4.8", "main", "list-keys.colons"));
        Assert.Equal(colons.Count, lines.Length);
        for (int i = 0; i < lines.Length; i++)
        {
            string letter = lines[i].Split(':')[8];
            OwnerTrustEntry e = db.Find(Convert.FromHexString(colons[i].Fingerprint))!;
            Assert.Equal(letter, e.Level switch
            {
                OwnerTrustLevel.Never => "n",
                OwnerTrustLevel.Marginal => "m",
                OwnerTrustLevel.Full => "f",
                OwnerTrustLevel.Ultimate => "u",
                _ => "-",
            });
        }
    }

    [Fact]
    public void ExportTextRoundTripsAndRejectsGarbage()
    {
        string text = File.ReadAllText(GnuPGHomes.Dir("2.4.8", "main", "ownertrust.txt"));
        var parsed = OwnerTrustExport.Parse(text);
        Assert.Equal(string.Concat(text.Split('\n').Where(l => l.Length > 0 && l[0] != '#').Select(l => l + "\n")), OwnerTrustExport.Format(parsed));
        Assert.Throws<GnuPGFormatException>(() => OwnerTrustExport.Parse("not a fingerprint:3:\n"));
        Assert.Throws<GnuPGFormatException>(() => OwnerTrustExport.Parse(new string('A', 40) + ":999:\n"));
    }

    [Fact]
    public void DamageIsATypedError()
    {
        byte[] good = File.ReadAllBytes(GnuPGHomes.Dir("2.4.8", "main", "trustdb.gpg"));
        Assert.False(TrustDb.TryParse(good.AsSpan(0, good.Length - 1), out _, out GnuPGFailure f));
        Assert.Equal(GnuPGError.Truncated, f.Error);
        byte[] bad = (byte[])good.Clone();
        bad[1] = (byte)'x';
        Assert.False(TrustDb.TryParse(bad, out _, out f));
        Assert.Equal(GnuPGError.BadHeader, f.Error);
    }
}
