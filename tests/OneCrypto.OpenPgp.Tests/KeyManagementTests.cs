using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using SymmetricAlgorithm = RecursiveAI.OneCrypto.OpenPgp.Packets.SymmetricAlgorithm;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>Key generation, editing, revocation, certification, passwords and two-phase signing.</summary>
[Collection("ProcessMemory")]
public class KeyManagementTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset T1 = T0.AddDays(10);

    private static byte[] Pw(string s) => Encoding.UTF8.GetBytes(s);

    private static bool Supported(PgpKeyProfile p) =>
        p is not (PgpKeyProfile.Rfc9980Pqc or PgpKeyProfile.Rfc9980PqcHigh) || (MLDsa.IsSupported && MLKem.IsSupported);

    private static PgpCertificate Generate(PgpKeyProfile profile, string? password = null, params string[] uids) =>
        PgpKeyGenerator.Generate(new PgpKeyGenerationOptions { Now = T0, Profile = profile, UserIds = uids.Length == 0 ? ["Alice <alice@example.org>"] : uids, Password = password is null ? null : Pw(password) });

    private static PgpSecretKey Unlock(PgpCertificate c, string? password = null) =>
        PgpSecretKey.Unlock(c.Primary, password is null ? [] : [Pw(password)]);

    public static TheoryData<PgpKeyProfile, bool> Profiles()
    {
        var d = new TheoryData<PgpKeyProfile, bool>();
        foreach (PgpKeyProfile p in Enum.GetValues<PgpKeyProfile>())
        {
            d.Add(p, false);
            d.Add(p, true);
        }

        return d;
    }

    [Fact]
    public void ACompletedSignatureWithTooFewFieldsIsRefusedNotIndexed()
    {
        // a minimized fuzz input: a saved state whose key is ECDSA, completed with a signature of the wrong shape
        byte[] state = File.ReadAllBytes(Path.Combine(TestFiles.TestData, "fuzz-repros", "pgpkey-prepared-signature-too-few-fields.bin"));
        Assert.True(PgpPreparedSignature.TryDecode(state, out PgpPreparedSignature? p, out _));
        Assert.Throws<PgpException>(() => p!.Complete(new byte[64]));
    }

    [Fact]
    public void ASecretKeyWithAnArgon2SpecifierOfZeroLanesIsATypedFailure()
    {
        // a minimized fuzz input: the S2K says Argon2 with parallelism 0
        byte[] key = File.ReadAllBytes(Path.Combine(TestFiles.TestData, "fuzz-repros", "pgpkey-argon2-zero-parallelism.bin"));
        foreach (PgpCertificate c in PgpCertificate.ParseAll(key))
        {
            foreach (PgpKey k in c.Keys)
            {
                Assert.Throws<PgpException>(() => PgpSecretKey.TryUnlock(k, [Pw("x"), []], out _)); // typed, like an Argon2 cost over the limit
            }
        }
    }

    [Fact]
    public void ASecretThatDoesNotMatchAnEcPointIsATypedFailure()
    {
        // found by fuzzing: an unprotected secret whose public point was altered unlocks, and the platform then refuses the pair
        byte[] bytes = Generate(PgpKeyProfile.NistP256).Export();
        byte[] q = PgpCertificate.Parse(bytes).Primary.Packet.Material.Values[0].ToArray();
        int at = bytes.AsSpan().IndexOf(q);
        Assert.True(at >= 0);
        bytes[at + q.Length - 1] ^= 0x01;
        PgpCertificate altered = PgpCertificate.Parse(bytes);
        using PgpSecretKey k = PgpSecretKey.Unlock(altered.Primary, []);
        Assert.Throws<PgpException>(() => k.SigningKey);
    }

    [Theory]
    [MemberData(nameof(Profiles))]
    public void GeneratedKeysSignEncryptAndDecrypt(PgpKeyProfile profile, bool protectedKey)
    {
        if (!Supported(profile))
        {
            return;
        }

        PgpCertificate key = Generate(profile, protectedKey ? "correct horse" : null);
        Assert.True(key.HasSecretKeyMaterial);
        PgpCertificate reread = PgpCertificate.Parse(key.Export(armor: true));
        Assert.Equal(key.Fingerprint, reread.Fingerprint);
        PgpCertificate pub = PgpCertificate.Parse(key.ExportPublic(armor: true));
        Assert.False(pub.HasSecretKeyMaterial);
        Assert.True(pub.Primary.StateAt(T1).IsValid);
        Assert.Equal(2, pub.Keys.Count);
        Assert.Equal(PgpKeyUsage.Certify | PgpKeyUsage.Sign, pub.Primary.StateAt(T1).Usage);
        byte expectedVersion = profile is PgpKeyProfile.Rfc9580 or PgpKeyProfile.Rfc9580Ed448 or PgpKeyProfile.Rfc9580Rsa or PgpKeyProfile.Rfc9980Pqc or PgpKeyProfile.Rfc9980PqcHigh ? (byte)6 : (byte)4;
        Assert.All(pub.Keys, k => Assert.Equal(expectedVersion, k.Packet.Version));

        byte[] password = protectedKey ? Pw("correct horse") : [];
        if (protectedKey)
        {
            Assert.Throws<PgpException>(() => PgpSecretKey.Unlock(key.Primary, [Pw("wrong")]));
            Assert.All(reread.Keys, k => Assert.True(((SecretKeyPacket)k.Packet).Protection.IsProtected));
        }

        Assert.NotNull(pub.FindSigningKey(T1)); // every profile, composite ML-DSA included, is picked for signing
        using PgpSecretKey signer = PgpSecretKey.Unlock(key.Primary, protectedKey ? [password] : []);
        using var sig = new MemoryStream();
        PgpMessageWriter.SignDetached(new MemoryStream("data"u8.ToArray()), sig, new PgpWriteOptions { Now = T1, Signers = [signer] });
        PgpReadResult r = PgpMessageReader.VerifyDetached(new MemoryStream("data"u8.ToArray()), new MemoryStream(sig.ToArray()), new PgpReadOptions { Now = T1, Certificates = [pub] });
        Assert.True(r.Signatures.Single().IsValid, string.Join("; ", r.Signatures.Single().Reasons));

        using var enc = new MemoryStream();
        PgpMessageWriter.Write(new MemoryStream("secret message"u8.ToArray()), enc, new PgpWriteOptions { Now = T1, Recipients = [pub] });
        using var dec = new MemoryStream();
        PgpMessageReader.Read(new MemoryStream(enc.ToArray()), dec, new PgpReadOptions { Now = T1, SecretKeys = [reread], KeyPasswords = protectedKey ? [password] : [] });
        Assert.Equal("secret message", Encoding.UTF8.GetString(dec.ToArray()));
    }

    [Fact]
    public void SigningOnlyKeyHasNoEncryptionSubkeyAndNoUserIdKeyStillBinds()
    {
        PgpCertificate key = PgpKeyGenerator.Generate(new PgpKeyGenerationOptions { Now = T0, SigningOnly = true });
        Assert.Single(key.Keys);
        Assert.True(key.Primary.StateAt(T1).IsValid);
        Assert.Empty(key.UserIds);
        PgpCertificate v4 = PgpKeyGenerator.Generate(new PgpKeyGenerationOptions { Now = T0, Profile = PgpKeyProfile.Rfc4880Curve25519 });
        Assert.True(v4.Primary.StateAt(T1).IsValid);
    }

    [Fact]
    public void GeneratedKeysCarryExpiryAndPreferences()
    {
        PgpCertificate key = PgpKeyGenerator.Generate(new PgpKeyGenerationOptions { Now = T0, UserIds = ["A"], ValidFor = TimeSpan.FromDays(30) });
        Assert.Equal(T0.AddDays(30), key.Primary.StateAt(T1).ExpiresAt);
        Assert.False(key.Primary.StateAt(T0.AddDays(31)).IsValid);
        Assert.False(key.Keys[1].StateAt(T0.AddDays(31)).IsValid);
        Assert.Equal(0x09, key.Primary.Features(T1));
    }

    private static List<byte[]> Encoded(TransferableKey k) => k.Packets.Select(p => p.ToArray()).ToList();

    private static void AssertKeepsPackets(PgpCertificate before, PgpCertificate after, int allowedNew)
    {
        List<byte[]> a = Encoded(before.Transferable);
        List<byte[]> b = Encoded(after.Transferable);
        // Every original packet is still there, byte for byte and in the same relative order.
        int at = 0;
        foreach (byte[] p in a)
        {
            while (at < b.Count && !b[at].AsSpan().SequenceEqual(p))
            {
                at++;
            }

            Assert.True(at < b.Count, "an untouched packet was lost or changed");
            at++;
        }

        Assert.Equal(a.Count + allowedNew, b.Count);
    }

    [Fact]
    public void EditsLeaveUntouchedPacketsByteIdentical()
    {
        // RFC 9580 Appendix A.4: a version 6 transferable secret key.
        PgpCertificate key = PgpCertificate.Parse(File.ReadAllBytes(TestFiles.OpenPgp("rfc9580", "A_4.asc")));
        using PgpSecretKey primary = PgpSecretKey.Unlock(key.Primary);

        PgpCertificate added = PgpKeyEditor.AddUserId(key, primary, "Alice <alice@work.example>", T1);
        AssertKeepsPackets(key, added, 2);
        Assert.Contains("Alice <alice@work.example>", added.UserIds);

        PgpCertificate removed = PgpKeyEditor.RemoveUserId(added, "Alice <alice@work.example>");
        Assert.Equal(Encoded(key.Transferable), Encoded(removed.Transferable));

        PgpCertificate expiry = PgpKeyEditor.SetExpiry(key, primary, T1.AddDays(100), T1);
        AssertKeepsPackets(key, expiry, 1);
        Assert.Equal(T1.AddDays(100), expiry.Primary.StateAt(T1).ExpiresAt);
        Assert.False(expiry.Primary.StateAt(T1.AddDays(101)).IsValid);
        PgpCertificate never = PgpKeyEditor.SetExpiry(expiry, primary, null, T1.AddDays(1));
        Assert.Null(never.Primary.StateAt(T1.AddDays(2)).ExpiresAt);

        PgpCertificate flags = PgpKeyEditor.SetKeyFlags(key, primary, PgpKeyUsage.Certify, T1);
        Assert.Equal(PgpKeyUsage.Certify, flags.Primary.StateAt(T1.AddDays(1)).Usage);

        PgpCertificate prefs = PgpKeyEditor.SetPreferences(key, primary, new PgpKeyPreferences { Symmetric = [SymmetricAlgorithm.Aes128], Features = 0x01 }, T1);
        Assert.Equal(0x01, prefs.Primary.Features(T1.AddDays(1)));
        Assert.Equal([(byte)SymmetricAlgorithm.Aes128], prefs.Primary.PreferredSymmetric(T1.AddDays(1)).ToArray());
    }

    [Fact]
    public void SubkeysAreAddedBoundAndRemoved()
    {
        PgpCertificate key = Generate(PgpKeyProfile.Rfc9580);
        using PgpSecretKey primary = Unlock(key);
        PgpCertificate withSigning = PgpKeyEditor.AddSubkey(key, primary, PgpSubkeyKind.Signing, T1, T1.AddDays(5));
        PgpKey sub = withSigning.Keys[^1];
        Assert.Equal(PgpKeyUsage.Sign, sub.StateAt(T1).Usage);
        Assert.True(sub.StateAt(T1.AddDays(1)).IsValid);
        Assert.False(sub.StateAt(T1.AddDays(6)).IsValid);

        // The new signing subkey signs, and its signature verifies against the certificate.
        using PgpSecretKey subSecret = PgpSecretKey.Unlock(sub);
        using var sig = new MemoryStream();
        PgpMessageWriter.SignDetached(new MemoryStream("x"u8.ToArray()), sig, new PgpWriteOptions { Now = T1.AddDays(1), Signers = [subSecret] });
        PgpReadResult r = PgpMessageReader.VerifyDetached(new MemoryStream("x"u8.ToArray()), new MemoryStream(sig.ToArray()), new PgpReadOptions { Now = T1.AddDays(1), Certificates = [withSigning.ToPublicCertificate()] });
        Assert.True(r.Signatures.Single().IsValid, string.Join("; ", r.Signatures.Single().Reasons));

        PgpCertificate without = PgpKeyEditor.RemoveSubkey(withSigning, sub.Fingerprint);
        Assert.Equal(Encoded(key.Transferable), Encoded(without.Transferable));
    }

    [Fact]
    public void ChangingTheExpiryOfASigningSubkeyKeepsItsBackSignature()
    {
        PgpCertificate key = Generate(PgpKeyProfile.Rfc4880Curve25519);
        using PgpSecretKey primary = Unlock(key);
        PgpCertificate withSigning = PgpKeyEditor.AddSubkey(key, primary, PgpSubkeyKind.Signing, T1, null);
        PgpKey sub = withSigning.Keys[^1];
        PgpCertificate renewed = PgpKeyEditor.SetExpiry(withSigning, primary, T1.AddDays(50), T1.AddDays(2), sub);
        Assert.True(renewed.Keys[^1].StateAt(T1.AddDays(3)).IsValid);
        Assert.Equal(T1.AddDays(50), renewed.Keys[^1].StateAt(T1.AddDays(3)).ExpiresAt);
    }

    [Fact]
    public void PrimaryUserIdCanBeChanged()
    {
        PgpCertificate key = Generate(PgpKeyProfile.Rfc4880Curve25519, null, "One", "Two");
        using PgpSecretKey primary = Unlock(key);
        PgpCertificate result = PgpKeyEditor.SetPrimaryUserId(key, primary, "Two", T1);
        foreach (UserComponent u in result.Transferable.Users)
        {
            SignaturePacket last = u.Signatures[^1];
            Assert.Equal(((UserIdPacket)u.Identity).Text == "Two", last.IsPrimaryUserId);
        }

        Assert.Throws<PgpException>(() => PgpKeyEditor.SetPrimaryUserId(key, primary, "Three", T1));
    }

    [Theory]
    [InlineData(PgpRevocationReason.None, true)]
    [InlineData(PgpRevocationReason.Compromised, true)]
    [InlineData(PgpRevocationReason.Superseded, false)]
    [InlineData(PgpRevocationReason.Retired, false)]
    public void KeyRevocationIsHardOrSoft(PgpRevocationReason reason, bool hard)
    {
        PgpCertificate key = Generate(PgpKeyProfile.Rfc9580);
        using PgpSecretKey primary = Unlock(key);
        PgpCertificate revoked = PgpKeyEditor.RevokeKey(key.ToPublicCertificate(), primary, reason, "test", T1);
        Assert.False(revoked.Primary.StateAt(T1.AddDays(1)).IsValid);
        Assert.Equal(!hard, revoked.Primary.StateAt(T0.AddDays(1)).IsValid);
        Assert.Equal((byte)reason, revoked.Transferable.DirectSignatures[^1].ReasonForRevocation!.Value.Code);

        // A stand-alone revocation certificate merged into the certificate has the same effect.
        PgpCertificate cert = key.ToPublicCertificate();
        PgpCertificate rc = PgpKeyEditor.CreateRevocationCertificate(key, primary, reason, "test", T1);
        Assert.Equal(2, rc.Transferable.Packets.Count);
        PgpCertificate merged = PgpKeyEditor.Merge(cert, rc);
        Assert.False(merged.Primary.StateAt(T1.AddDays(1)).IsValid);
    }

    [Fact]
    public void SubkeyAndUserIdRevocation()
    {
        PgpCertificate key = Generate(PgpKeyProfile.Rfc9580);
        using PgpSecretKey primary = Unlock(key);
        PgpCertificate r1 = PgpKeyEditor.RevokeSubkey(key, primary, key.Keys[1].Fingerprint, PgpRevocationReason.Retired, "old", T1);
        Assert.False(r1.Keys[1].StateAt(T1.AddDays(1)).IsValid);
        Assert.True(r1.Keys[1].StateAt(T0.AddDays(1)).IsValid);
        Assert.True(r1.Primary.StateAt(T1.AddDays(1)).IsValid);

        PgpCertificate r2 = PgpKeyEditor.RevokeUserId(key, primary, "Alice <alice@example.org>", PgpRevocationReason.UserIdNoLongerValid, "moved", T1);
        Assert.False(PgpUserIds.HasSelfSignature(r2, "Alice <alice@example.org>", T1.AddDays(1)));
        Assert.True(PgpUserIds.HasSelfSignature(r2, "Alice <alice@example.org>", T0.AddDays(1)));
    }

    [Theory]
    [InlineData(PgpCertificationLevel.Generic)]
    [InlineData(PgpCertificationLevel.Persona)]
    [InlineData(PgpCertificationLevel.Casual)]
    [InlineData(PgpCertificationLevel.Positive)]
    public void ThirdPartyCertificationsAreHonouredAndRevocable(PgpCertificationLevel level)
    {
        PgpCertificate alice = Generate(PgpKeyProfile.Rfc9580);
        PgpCertificate bob = Generate(PgpKeyProfile.Rfc4880Curve25519, null, "Bob <bob@example.org>");
        using PgpSecretKey bobKey = Unlock(bob);
        PgpCertificate pub = alice.ToPublicCertificate();
        const string uid = "Alice <alice@example.org>";
        Assert.False(PgpUserIds.IsCertified(pub, uid, [bob.ToPublicCertificate()], T1));

        PgpCertificate certified = PgpKeyEditor.Certify(pub, uid, bobKey, T1, new PgpCertificationOptions { Level = level });
        PgpCertificate bobPub = bob.ToPublicCertificate();
        Assert.True(PgpUserIds.IsCertified(certified, uid, [bobPub], T1.AddDays(1)));
        Assert.True(PgpUserIds.IsCertified(certified, "alice@example.org", [bobPub], T1.AddDays(1), addrSpecOnly: true));
        Assert.False(PgpUserIds.IsCertified(certified, uid, [bobPub], T0)); // before the certification was made
        Assert.False(PgpUserIds.IsCertified(certified, "Someone else", [bobPub], T1.AddDays(1)));
        Assert.Equal((byte)level, certified.Transferable.Users[0].Signatures[^1].SignatureTypeId);

        PgpCertificate revoked = PgpKeyEditor.RevokeCertification(certified, uid, bobKey, PgpRevocationReason.None, "no longer", T1.AddDays(2));
        Assert.False(PgpUserIds.IsCertified(revoked, uid, [bobPub], T1.AddDays(3)));
        Assert.True(PgpUserIds.IsCertified(revoked, uid, [bobPub], T1.AddDays(1)));
    }

    [Fact]
    public void TrustSignaturesCarryLevelAmountAndRegex()
    {
        PgpCertificate alice = Generate(PgpKeyProfile.Rfc9580);
        PgpCertificate bob = Generate(PgpKeyProfile.Rfc9580, null, "Bob");
        using PgpSecretKey bobKey = Unlock(bob);
        PgpCertificate c = PgpKeyEditor.Certify(alice.ToPublicCertificate(), "Alice <alice@example.org>", bobKey, T1,
            new PgpCertificationOptions { TrustLevel = 1, TrustAmount = 120, Regex = "<[^>]+[@.]example\\.org>$", Exportable = false });
        SignaturePacket s = c.Transferable.Users[0].Signatures[^1];
        Assert.Equal((1, 120), ((int)s.TrustSignature!.Value.Level, (int)s.TrustSignature.Value.Amount));
        Assert.False(s.Exportable);
        Assert.NotNull(s.HashedSubpackets.Find(SubpacketType.RegularExpression));
    }

    [Fact]
    public void CertifyingARequiredSelfSignedUserIdOnly()
    {
        PgpCertificate alice = Generate(PgpKeyProfile.Rfc9580);
        PgpCertificate bob = Generate(PgpKeyProfile.Rfc9580, null, "Bob");
        using PgpSecretKey bobKey = Unlock(bob);
        PgpCertificate pub = alice.ToPublicCertificate();
        Assert.Throws<PgpException>(() => PgpKeyEditor.Certify(pub, "Alice the second", bobKey, T1));
        PgpCertificate added = PgpKeyEditor.Certify(pub, "Alice the second", bobKey, T1, requireSelfSignature: false);
        Assert.Contains("Alice the second", added.UserIds);
        Assert.True(PgpUserIds.IsCertified(added, "Alice the second", [bob.ToPublicCertificate()], T1.AddDays(1)));
    }

    [Fact]
    public void PasswordsAreChangedAndRemoved()
    {
        PgpCertificate plain = Generate(PgpKeyProfile.Rfc9580);
        PgpCertificate locked = PgpKeyEditor.SetPassword(plain, [], Pw("one"));
        Assert.All(locked.Keys, k => Assert.True(((SecretKeyPacket)k.Packet).Protection.IsProtected));
        var sp = (SecretKeyPacket)locked.Primary.Packet;
        Assert.Equal(253, sp.Protection.Usage);
        Assert.Equal(S2kType.Argon2, sp.Protection.S2k!.Type);

        PgpCertificate changed = PgpKeyEditor.SetPassword(locked, [Pw("one")], Pw("two"));
        Assert.Throws<PgpException>(() => PgpSecretKey.Unlock(changed.Primary, [Pw("one")]));
        using (PgpSecretKey.Unlock(changed.Primary, [Pw("two")]))
        {
        }

        var e = Assert.Throws<PgpException>(() => PgpKeyEditor.SetPassword(locked, [Pw("nope")], null));
        Assert.Equal(PgpFailure.KeyIsProtected, e.Failure);

        PgpCertificate open = PgpKeyEditor.SetPassword(changed, [Pw("two")], null);
        Assert.False(((SecretKeyPacket)open.Primary.Packet).Protection.IsProtected);
        // The same secret comes back out: the public parts and signatures are untouched.
        Assert.Equal(plain.Fingerprint, open.Fingerprint);
        using PgpSecretKey a = PgpSecretKey.Unlock(plain.Primary);
        using PgpSecretKey b = PgpSecretKey.Unlock(open.Primary);
        Assert.Equal(a.SecretParts()[0], b.SecretParts()[0]);

        // Version 4 keys use CFB with a SHA-1 check and an iterated and salted S2K.
        PgpCertificate v4 = PgpKeyEditor.SetPassword(Generate(PgpKeyProfile.Rfc4880Curve25519), [], Pw("v4"));
        var sp4 = (SecretKeyPacket)v4.Primary.Packet;
        Assert.Equal(254, sp4.Protection.Usage);
        Assert.Equal(S2kType.IteratedSalted, sp4.Protection.S2k!.Type);
    }

    [Fact]
    public void MergeAddsMissingSignaturesAndComponents()
    {
        PgpCertificate alice = Generate(PgpKeyProfile.Rfc9580);
        PgpCertificate bob = Generate(PgpKeyProfile.Rfc9580, null, "Bob");
        using PgpSecretKey bobKey = Unlock(bob);
        using PgpSecretKey aliceKey = Unlock(alice);
        PgpCertificate pub = alice.ToPublicCertificate();
        PgpCertificate certified = PgpKeyEditor.Certify(pub, "Alice <alice@example.org>", bobKey, T1);
        PgpCertificate withUid = PgpKeyEditor.AddUserId(pub.Transferable.IsSecret ? pub : alice, aliceKey, "Alice 2", T1).ToPublicCertificate();

        PgpCertificate merged = PgpKeyEditor.Merge(pub, certified);
        Assert.Equal(pub.Transferable.Packets.Count + 1, merged.Transferable.Packets.Count);
        PgpCertificate both = PgpKeyEditor.Merge(merged, withUid);
        Assert.Equal(2, both.Transferable.Users.Count);
        Assert.True(PgpUserIds.IsCertified(both, "Alice <alice@example.org>", [bob.ToPublicCertificate()], T1.AddDays(1)));
        // Merging twice adds nothing.
        Assert.Equal(Encoded(both.Transferable), Encoded(PgpKeyEditor.Merge(both, certified).Transferable));
        Assert.Throws<PgpException>(() => PgpKeyEditor.Merge(pub, bob.ToPublicCertificate()));
        // A secret key absorbs a certificate without losing its secrets.
        PgpCertificate secretMerged = PgpKeyEditor.Merge(alice, certified);
        Assert.True(secretMerged.HasSecretKeyMaterial);
    }

    [Fact]
    public void RefreshRemovesWeakPreferencesAndAddsAnEncryptionSubkey()
    {
        PgpCertificate key = PgpKeyGenerator.Generate(new PgpKeyGenerationOptions { Now = T0, UserIds = ["Old"], SigningOnly = true });
        using PgpSecretKey primary = Unlock(key);
        PgpCertificate weak = PgpKeyEditor.SetPreferences(key, primary, new PgpKeyPreferences { Hash = [PgpHashAlgorithm.Sha1, PgpHashAlgorithm.Sha256] }, T0.AddDays(1));
        PgpCertificate fresh = PgpKeyEditor.Refresh(weak, primary, T1, signingOnly: false, noAddedCapabilities: false);
        Assert.Equal(2, fresh.Keys.Count);
        Assert.True(fresh.Keys[1].StateAt(T1.AddDays(1)).IsValid);
        SignaturePacket last = fresh.Transferable.DirectSignatures[^1];
        Assert.Equal([(byte)PgpHashAlgorithm.Sha256], last.PreferredHashAlgorithms!.Value.ToArray());
        Assert.Equal(fresh.Fingerprint, key.Fingerprint);
    }

    [Theory]
    [InlineData(PgpKeyProfile.Rfc9580)]
    [InlineData(PgpKeyProfile.Rfc4880Rsa)]
    [InlineData(PgpKeyProfile.NistP256)]
    [InlineData(PgpKeyProfile.Rfc9580Ed448)]
    public void TwoPhaseSigningSurvivesSerialisation(PgpKeyProfile profile)
    {
        PgpCertificate key = Generate(profile);
        PgpCertificate pub = key.ToPublicCertificate();
        byte[] data = new byte[100_000];
        new Random(3).NextBytes(data);
        PgpPreparedSignature prepared = PgpPreparedSignature.PrepareDetached(pub.Primary, new MemoryStream(data), T1);
        byte[] state = prepared.Encode();

        // "Another process": only the serialised state and the private key meet.
        PgpPreparedSignature again = PgpPreparedSignature.Decode(state);
        Assert.Equal(prepared.ToSign.ToArray(), again.ToSign.ToArray());
        using PgpSecretKey secret = Unlock(key);
        byte[] raw = again.Input == SigningInput.Digest ? secret.SigningKey.SignDigest(again.ToSign.Span, again.Spec) : secret.SigningKey.Sign(again.ToSign.Span, again.Spec);
        byte[] signature = again.Complete(raw);

        PgpReadResult r = PgpMessageReader.VerifyDetached(new MemoryStream(data), new MemoryStream(signature), new PgpReadOptions { Now = T1, Certificates = [pub] });
        Assert.True(r.Signatures.Single().IsValid, string.Join("; ", r.Signatures.Single().Reasons));
        Assert.NotEmpty(prepared.SignWith(secret.SigningKey));

        // A signature from another key, or over other data, is refused before anything is assembled.
        using PgpSecretKey other = Unlock(Generate(profile));
        byte[] wrong = again.Input == SigningInput.Digest ? other.SigningKey.SignDigest(again.ToSign.Span, again.Spec) : other.SigningKey.Sign(again.ToSign.Span, again.Spec);
        Assert.Throws<PgpException>(() => again.Complete(wrong));
        Assert.False(PgpPreparedSignature.TryDecode(state.AsSpan(0, state.Length - 3), out _, out string? error));
        Assert.NotNull(error);
    }

    [Fact]
    public void TextSignaturesAndTamperedStateAreHandled()
    {
        PgpCertificate key = Generate(PgpKeyProfile.Rfc4880Curve25519);
        PgpPreparedSignature p = PgpPreparedSignature.PrepareDetached(key.Primary, new MemoryStream("a\nb\n"u8.ToArray()), T1, text: true);
        Assert.Equal(SignatureType.Text, p.Type);
        byte[] state = p.Encode();
        byte[] bad = (byte[])state.Clone();
        bad[state.Length - 5] ^= 0xFF;
        // Changing the digest leaves a state that decodes but whose completion cannot verify.
        PgpPreparedSignature changed = PgpPreparedSignature.Decode(bad);
        using PgpSecretKey secret = Unlock(key);
        Assert.Throws<PgpException>(() => changed.Complete(changed.Input == SigningInput.Digest ? secret.SigningKey.SignDigest(p.ToSign.Span, p.Spec) : secret.SigningKey.Sign(p.ToSign.Span, p.Spec)));
    }

    [Fact]
    public void HappyPathCallsWork()
    {
        PgpCertificate key = Pgp.GenerateKey("Carol <carol@example.org>", "pw");
        PgpCertificate open = Pgp.ChangePassword(key, "pw", null);
        Assert.False(((SecretKeyPacket)open.Primary.Packet).Protection.IsProtected);
        PgpCertificate revoked = Pgp.Revoke(open);
        Assert.False(revoked.HasSecretKeyMaterial);
        Assert.False(revoked.Primary.StateAt(TimeProvider.System.GetUtcNow().AddSeconds(5)).IsValid);
        PgpCertificate dave = Pgp.GenerateKey("Dave");
        PgpCertificate certified = Pgp.Certify(open.ToPublicCertificate(), "Carol <carol@example.org>", dave);
        Assert.Equal(open.ToPublicCertificate().Transferable.Packets.Count + 1, certified.Transferable.Packets.Count);
    }
}
