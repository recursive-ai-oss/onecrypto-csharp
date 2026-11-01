using RecursiveAI.OneCrypto.OpenPgp.CertD;
using RecursiveAI.OneCrypto.OpenPgp.GnuPG;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

public sealed class CertDirectoryTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "certd-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    private static IReadOnlyList<TransferableKey> Export(string version = "2.4.8") => LegacyKeyring.Read(File.ReadAllBytes(GnuPGHomes.Dir(version, "main", "export.pgp")));

    private static byte[] Bytes(TransferableKey k)
    {
        using var ms = new MemoryStream();
        k.WriteTo(ms);
        return ms.ToArray();
    }

    // A certificate with a direct signature, two user IDs and a second signature on the first one, spliced from two exported certificates.
    // The merge works on packet identity and does not check signatures, so borrowed signatures are enough to exercise it.
    private static TransferableKey Rich()
    {
        IReadOnlyList<TransferableKey> all = Export();
        TransferableKey x = all[0];
        TransferableKey y = all[1];
        TransferableKey z = all[2];
        var list = new List<Packet> { x.Primary, y.Subkeys[0].Signatures[0], x.Users[0].Identity };
        list.AddRange(x.Users[0].Signatures);
        list.Add(y.Users[0].Signatures[0]);
        list.Add(z.Users[0].Identity);
        list.AddRange(z.Users[0].Signatures);
        list.Add(x.Subkeys[0].Key);
        list.AddRange(x.Subkeys[0].Signatures);
        return TransferableKey.Parse(list);
    }

    private static TransferableKey Without(TransferableKey k, Func<Packet, bool> drop) => TransferableKey.Parse(k.Packets.Where(p => !drop(p)).ToList());

    [Fact]
    public void NamesMapToPathsAsTheDraftDescribes()
    {
        string sep = Path.DirectorySeparatorChar.ToString();
        Assert.Equal("eb" + sep + "85bb5fa33a75e15e944e63f231550c4f47e38e", CertDirectory.RelativePath("EB85BB5FA33A75E15E944E63F231550C4F47E38E"));
        Assert.Equal("trust-root", CertDirectory.RelativePath("trust-root"));
        foreach (string bad in new[] { "", "../../etc/passwd", "eb85", "zz85bb5fa33a75e15e944e63f231550c4f47e38e", "trust-root/x", "eb85bb5fa33a75e15e944e63f231550c4f47e38e0" })
        {
            Assert.False(CertDirectory.IsValidName(bad), bad);
            Assert.Throws<GnuPGFormatException>(() => CertDirectory.RelativePath(bad));
        }

        Assert.True(CertDirectory.IsValidName(new string('a', 64)));
    }

    [Fact]
    public void DefaultPathFollowsTheEnvironmentVariable()
    {
        string? old = Environment.GetEnvironmentVariable("PGP_CERT_D");
        try
        {
            Environment.SetEnvironmentVariable("PGP_CERT_D", "/somewhere/certs");
            Assert.Equal("/somewhere/certs", CertDirectory.DefaultPath());
        }
        finally
        {
            Environment.SetEnvironmentVariable("PGP_CERT_D", old);
        }

        Assert.EndsWith("pgp.cert.d", CertDirectory.DefaultPath(), StringComparison.Ordinal);
    }

    [Fact]
    public void InsertedCertificatesAreFoundByFingerprintAndKeepTheirBytes()
    {
        var store = CertDirectory.Open(_dir);
        var certs = Export();
        foreach (TransferableKey c in certs)
        {
            CertEntry e = store.Insert(c);
            Assert.Equal(c.Primary.FingerprintHex.ToLowerInvariant(), e.Name);
            Assert.Equal(Bytes(c), e.Data.ToArray());
        }

        Assert.True(File.Exists(Path.Combine(_dir, "writelock")));
        var listed = store.Enumerate().ToList();
        Assert.Equal(certs.Count, listed.Count);
        foreach (TransferableKey c in certs)
        {
            CertEntry? got = store.Get(c.Primary.FingerprintHex);
            Assert.NotNull(got);
            Assert.Equal(Bytes(c), got!.Data.ToArray());
            Assert.Equal(c.Primary.FingerprintHex, got.ReadKey().Primary.FingerprintHex);
            Assert.Equal(c.Primary.FingerprintHex.ToLowerInvariant()[..2], new DirectoryInfo(Path.GetDirectoryName(Path.Combine(_dir, CertDirectory.RelativePath(got.Name)))!).Name);
        }

        Assert.Null(store.Get(new string('0', 40)));
        Assert.Null(store.Get(CertDirectory.TrustRoot));
    }

    [Fact]
    public void InsertingAgainChangesNothingAndKeepsTheTag()
    {
        var store = CertDirectory.Open(_dir);
        TransferableKey c = Export()[0];
        CertEntry first = store.Insert(c);
        CertEntry second = store.Insert(c);
        Assert.Equal(first.Tag, second.Tag);
        Assert.Null(store.GetIfChanged(first.Tag, first.Name));
    }

    [Fact]
    public void ATrustPacketOfTheIncomingCopyIsNotStored()
    {
        var store = CertDirectory.Open(_dir);
        TransferableKey withTrust = LegacyKeyring.Read(File.ReadAllBytes(GnuPGHomes.Dir("2.4.8", "legacy", "pubring.gpg")))[0];
        Assert.Contains(withTrust.Packets, p => p.TagId == (byte)PacketTag.Trust);
        CertEntry e = store.Insert(withTrust);
        Assert.DoesNotContain(e.ReadKey().Packets, p => p.TagId == (byte)PacketTag.Trust);
        Assert.Equal(withTrust.Primary.FingerprintHex, e.ReadKey().Primary.FingerprintHex);
    }

    [Fact]
    public void MergeAddsMissingSignaturesUserIdsAndSubkeysAndLeavesTheRestAsStored()
    {
        TransferableKey withSub = Export()[0];
        TransferableKey twoUid = Rich();
        TransferableKey revoked = Rich();

        // Each case: store a reduced copy, insert the full one; the result is the full certificate, byte for byte, and the stored part is a prefix-preserving subset.
        foreach ((TransferableKey full, TransferableKey part) in new[]
        {
            (twoUid, Without(twoUid, p => p == twoUid.Users[1].Identity || twoUid.Users[1].Signatures.Contains(p))),
            (revoked, Without(revoked, p => revoked.DirectSignatures.Contains(p))),
            (withSub, Without(withSub, p => p == withSub.Subkeys[0].Key || withSub.Subkeys[0].Signatures.Contains(p))),
            (twoUid, Without(twoUid, p => p == twoUid.Users[0].Signatures[^1])),
        })
        {
            string d = Path.Combine(_dir, Guid.NewGuid().ToString("N"));
            var store = CertDirectory.Open(d);
            CertEntry partial = store.Insert(part);
            Assert.NotEqual(Bytes(full).Length, partial.Data.Length);
            CertEntry merged = store.Insert(full);
            Assert.Equal(Bytes(full), merged.Data.ToArray());
            Assert.NotEqual(partial.Tag, merged.Tag);

            // And the other way round: the full certificate is stored, a reduced copy adds nothing.
            string d2 = Path.Combine(_dir, Guid.NewGuid().ToString("N"));
            var store2 = CertDirectory.Open(d2);
            CertEntry fullEntry = store2.Insert(full);
            CertEntry again = store2.Insert(part);
            Assert.Equal(fullEntry.Tag, again.Tag);
            Assert.Equal(Bytes(full), again.Data.ToArray());
        }
    }

    [Fact]
    public void ASignatureThatDiffersOnlyInItsUnhashedAreaIsNotDuplicated()
    {
        TransferableKey c = Export()[0];
        SignaturePacket sig = c.Users[0].Signatures[0];
        // Rebuild the signature with an extra unhashed subpacket: same hashed data and values, so the same signature.
        byte[] body = sig.Body.ToArray();
        int hashedLen = (body[4] << 8) | body[5];
        int unhashedAt = 6 + hashedLen;
        int unhashedLen = (body[unhashedAt] << 8) | body[unhashedAt + 1];
        byte[] extra = [5, 0x1F, 1, 2, 3, 4]; // a private subpacket
        var changed = new List<byte>();
        changed.AddRange(body.AsSpan(0, unhashedAt).ToArray());
        int newLen = unhashedLen + extra.Length;
        changed.Add((byte)(newLen >> 8));
        changed.Add((byte)newLen);
        changed.AddRange(body.AsSpan(unhashedAt + 2, unhashedLen).ToArray());
        changed.AddRange(extra);
        changed.AddRange(body.AsSpan(unhashedAt + 2 + unhashedLen).ToArray());
        Packet altered = Packet.Create((byte)PacketTag.Signature, changed.ToArray());
        var packets = c.Packets.Select(p => p == sig ? altered : p).ToList();
        TransferableKey variant = TransferableKey.Parse(packets);

        var store = CertDirectory.Open(_dir);
        CertEntry first = store.Insert(c);
        CertEntry second = store.Insert(variant);
        Assert.Equal(first.Tag, second.Tag);
        Assert.Equal(Bytes(c), second.Data.ToArray());
    }

    [Fact]
    public void ConcurrentInsertsOfPartialCopiesLoseNothing()
    {
        TransferableKey full = Rich();
        TransferableKey a = Without(full, p => p == full.Users[1].Identity || full.Users[1].Signatures.Contains(p));
        TransferableKey b = Without(full, p => p == full.Users[0].Identity || full.Users[0].Signatures.Contains(p));
        TransferableKey bare = Without(full, p => full.Users.Any(u => p == u.Identity || u.Signatures.Contains(p)));

        var store = CertDirectory.Open(_dir);
        var tasks = new List<Task>();
        for (int i = 0; i < 24; i++)
        {
            TransferableKey pick = (i % 3) switch { 0 => a, 1 => b, _ => bare };
            tasks.Add(Task.Run(() => CertDirectory.Open(_dir).Insert(pick)));
        }

        Task.WaitAll([.. tasks]);
        TransferableKey result = store.Get(full.Primary.FingerprintHex)!.ReadKey();
        Assert.Equal(full.Users.Select(u => ((UserIdPacket)u.Identity).Text).Order().ToList(), result.Users.Select(u => ((UserIdPacket)u.Identity).Text).Order().ToList());
        Assert.Equal(full.Users.Sum(u => u.Signatures.Count), result.Users.Sum(u => u.Signatures.Count));
        Assert.Empty(Directory.GetFiles(Path.Combine(_dir, full.Primary.FingerprintHex.ToLowerInvariant()[..2]), ".tmp-*"));
    }

    [Fact]
    public void TheWriteLockExcludesAnotherWriter()
    {
        var store = CertDirectory.Open(_dir);
        store.LockTimeout = TimeSpan.FromMilliseconds(200);
        TransferableKey c = Export()[0];
        using (var held = new FileStream(Path.Combine(_dir, "writelock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
        {
            Assert.Throws<TimeoutException>(() => store.Insert(c));
            Assert.Null(store.Get(c.Primary.FingerprintHex)); // readers need no lock and nothing was written
        }

        Assert.NotNull(store.Insert(c));
    }

    [Fact]
    public void TheTrustRootIsAKeyAndMergesLikeACertificate()
    {
        var store = CertDirectory.Open(_dir);
        var secretKeys = LegacyKeyring.Read(File.ReadAllBytes(GnuPGHomes.Dir("2.4.8", "main", "export.pgp")));
        TransferableKey root = secretKeys[0];
        CertEntry e = store.InsertTrustRoot(root);
        Assert.Equal("trust-root", e.Name);
        Assert.Equal(Bytes(root), store.Get("trust-root")!.Data.ToArray());
        Assert.Empty(store.Enumerate()); // enumeration lists fingerprints only
        Assert.Throws<ArgumentException>(() => store.InsertTrustRoot(secretKeys[1]));
    }

    [Fact]
    public void ForeignFilesAndExtensionNamesAreIgnored()
    {
        var store = CertDirectory.Open(_dir);
        TransferableKey c = Export()[0];
        store.Insert(c);
        File.WriteAllText(Path.Combine(_dir, "_other_extension.sqlite"), "x");
        Directory.CreateDirectory(Path.Combine(_dir, "_scratch"));
        File.WriteAllText(Path.Combine(_dir, "README"), "x");
        Directory.CreateDirectory(Path.Combine(_dir, "zz"));
        File.WriteAllText(Path.Combine(_dir, "zz", "abc"), "x");
        Assert.Single(store.Enumerate());
    }

    [Fact]
    public void AFileWithTheWrongFingerprintOrGarbageIsATypedError()
    {
        var store = CertDirectory.Open(_dir);
        var certs = Export();
        string name = certs[1].Primary.FingerprintHex.ToLowerInvariant();
        string path = Path.Combine(_dir, CertDirectory.RelativePath(name));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, Bytes(certs[0])); // another certificate under this name
        Assert.Throws<GnuPGFormatException>(() => store.Get(name));
        File.WriteAllBytes(path, [1, 2, 3, 4]);
        Assert.Throws<GnuPGFormatException>(() => store.Get(name));
        Assert.Throws<DirectoryNotFoundException>(() => CertDirectory.Open(Path.Combine(_dir, "missing"), create: false));
    }

    [Fact]
    public void ACertificateDirectoryWrittenBySequoiaIsRead()
    {
        string root = Path.Combine(GnuPGHomes.Root, "..", "certd", "sq-1.5.0", "cert-d");
        var store = CertDirectory.Open(root, create: false);
        var expected = GnuPGHomes.ReadColons(GnuPGHomes.Dir("2.4.8", "main", "list-keys.colons")).Select(k => k.Fingerprint.ToLowerInvariant()).Order().ToList();
        var listed = store.Enumerate().ToList();
        Assert.Equal(expected, listed.Select(e => e.Name).Order().ToList());
        foreach (CertEntry e in listed)
        {
            TransferableKey k = e.ReadKey();
            Assert.Equal(e.Name, k.Primary.FingerprintHex.ToLowerInvariant());
        }
    }
}
