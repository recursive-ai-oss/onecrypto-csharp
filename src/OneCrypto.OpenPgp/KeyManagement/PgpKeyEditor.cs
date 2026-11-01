using System.Security.Cryptography;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Policy;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>
/// A transferable key opened for editing: the packets after each component head, in their original order, so that anything an edit does not
/// touch is written back exactly as it was read (byte for byte, trust packets and unknown packets included).
/// </summary>
internal sealed class KeyWork
{
    internal KeyWork(KeyPacket primary)
    {
        Primary = primary;
    }

    internal KeyPacket Primary { get; set; }

    internal List<Packet> PrimaryItems { get; } = [];

    internal List<UserWork> Users { get; } = [];

    internal List<SubWork> Subs { get; } = [];

    internal sealed class UserWork
    {
        internal UserWork(Packet identity) => Identity = identity;

        internal Packet Identity { get; }

        internal List<Packet> Items { get; } = [];
    }

    internal sealed class SubWork
    {
        internal SubWork(KeyPacket key) => Key = key;

        internal KeyPacket Key { get; set; }

        internal List<Packet> Items { get; } = [];
    }

    internal static KeyWork From(TransferableKey key)
    {
        var w = new KeyWork(key.Primary);
        UserWork? user = null;
        SubWork? sub = null;
        for (int i = 1; i < key.Packets.Count; i++)
        {
            Packet p = key.Packets[i];
            switch (p)
            {
                case UserIdPacket or UserAttributePacket:
                    user = new UserWork(p);
                    sub = null;
                    w.Users.Add(user);
                    break;
                case KeyPacket { IsSubkey: true } k:
                    sub = new SubWork(k);
                    user = null;
                    w.Subs.Add(sub);
                    break;
                default:
                    (sub is not null ? sub.Items : user is not null ? user.Items : w.PrimaryItems).Add(p);
                    break;
            }
        }

        return w;
    }

    internal TransferableKey ToKey()
    {
        var list = new List<Packet> { Primary };
        list.AddRange(PrimaryItems);
        foreach (UserWork u in Users)
        {
            list.Add(u.Identity);
            list.AddRange(u.Items);
        }

        foreach (SubWork s in Subs)
        {
            list.Add(s.Key);
            list.AddRange(s.Items);
        }

        return TransferableKey.Parse(list);
    }

    internal PgpCertificate ToCertificate() => PgpCertificate.FromTransferable(ToKey());
}

/// <summary>Why a key is revoked (RFC 9580 §5.2.3.31).</summary>
public enum PgpRevocationReason : byte
{
    /// <summary>No reason given. A hard revocation: the key is invalid at every time.</summary>
    None = 0,

    /// <summary>The key was replaced by another. A soft revocation: signatures made before it stay good.</summary>
    Superseded = 1,

    /// <summary>The key's secret part may have been disclosed. A hard revocation.</summary>
    Compromised = 2,

    /// <summary>The key is no longer used. A soft revocation.</summary>
    Retired = 3,

    /// <summary>The User ID is no longer valid. A soft revocation, for User IDs only.</summary>
    UserIdNoLongerValid = 32,
}

/// <summary>The role of a new subkey.</summary>
public enum PgpSubkeyKind
{
    /// <summary>Encrypts communications and storage.</summary>
    Encryption,

    /// <summary>Signs. The subkey proves it agrees with the binding by signing the primary key (RFC 9580 §5.2.1.8).</summary>
    Signing,

    /// <summary>Authenticates (key flag 0x20).</summary>
    Authentication,
}

/// <summary>How much a certifier vouches for a User ID (RFC 9580 §5.2.1.3).</summary>
public enum PgpCertificationLevel : byte
{
    /// <summary>Type 0x10: no claim about how carefully the identity was checked.</summary>
    Generic = 0x10,

    /// <summary>Type 0x11: the certifier has not verified the identity at all.</summary>
    Persona = 0x11,

    /// <summary>Type 0x12: some casual verification.</summary>
    Casual = 0x12,

    /// <summary>Type 0x13: substantial verification.</summary>
    Positive = 0x13,
}

/// <summary>Optional parts of a third-party certification (RFC 9580 §5.2.3.21 to §5.2.3.25).</summary>
public sealed class PgpCertificationOptions
{
    /// <summary>The level. Default <see cref="PgpCertificationLevel.Generic"/>.</summary>
    public PgpCertificationLevel Level { get; init; } = PgpCertificationLevel.Generic;

    /// <summary>For a trust signature (RFC 9580 §5.2.3.21): how many levels of introduction the target may make. Null for an ordinary certification.</summary>
    public byte? TrustLevel { get; init; }

    /// <summary>For a trust signature: the amount of trust, 0 to 255 (120 is "partial", 255 "complete" in the classic model). Default 120.</summary>
    public byte TrustAmount { get; init; } = 120;

    /// <summary>For a trust signature: a regular expression limiting the User IDs the target may introduce; null for none.</summary>
    public string? Regex { get; init; }

    /// <summary>False to mark the certification as local (not exportable). Default true.</summary>
    public bool Exportable { get; init; } = true;

    /// <summary>False to mark the certification as irrevocable. Default true.</summary>
    public bool Revocable { get; init; } = true;

    /// <summary>How long the certification stays valid; null for no expiry. Default null.</summary>
    public TimeSpan? ValidFor { get; init; }
}

/// <summary>Algorithm preferences and features a key advertises (RFC 9580 §5.2.3.14 to §5.2.3.22, §5.2.3.32). A null member is left as it is.</summary>
public sealed class PgpKeyPreferences
{
    /// <summary>Preferred symmetric ciphers, most preferred first.</summary>
    public IReadOnlyList<SymmetricAlgorithm>? Symmetric { get; init; }

    /// <summary>Preferred hashes, most preferred first.</summary>
    public IReadOnlyList<PgpHashAlgorithm>? Hash { get; init; }

    /// <summary>Preferred compression algorithms, most preferred first.</summary>
    public IReadOnlyList<CompressionAlgorithm>? Compression { get; init; }

    /// <summary>Preferred AEAD ciphersuites as (cipher, mode) pairs, most preferred first.</summary>
    public IReadOnlyList<(SymmetricAlgorithm Cipher, AeadAlgorithm Aead)>? AeadSuites { get; init; }

    /// <summary>The Features octet: 0x01 modification detection (SEIPD v1), 0x08 SEIPD v2.</summary>
    public byte? Features { get; init; }
}

/// <summary>
/// Edits OpenPGP certificates and keys (RFC 9580 §10.1, §5.2.1, §5.2.3). Every method returns a new certificate and leaves its input alone; the
/// packets an edit does not touch are kept exactly as read. Signatures are made by the primary key you pass in unlocked, at the time you pass in.
/// </summary>
public static class PgpKeyEditor
{
    // The subpackets that belong to one signature rather than to the key's properties; a re-issued self-signature does not inherit them.
    private static readonly HashSet<byte> PerSignature =
    [
        (byte)SubpacketType.SignatureCreationTime, (byte)SubpacketType.SignatureExpirationTime, (byte)SubpacketType.IssuerFingerprint,
        (byte)SubpacketType.IssuerKeyId, (byte)SubpacketType.PrimaryUserId, (byte)SubpacketType.EmbeddedSignature,
    ];

    // ---- helpers ----

    private static void RequireOwner(PgpCertificate cert, PgpSecretKey primary)
    {
        ArgumentNullException.ThrowIfNull(cert);
        ArgumentNullException.ThrowIfNull(primary);
        if (!cert.Primary.Fingerprint.AsSpan().SequenceEqual(primary.Key.Fingerprint))
        {
            throw new PgpException(PgpFailure.KeyCannotPerform, "The unlocked key is not the primary key of this certificate.");
        }
    }

    internal static bool Verifies(SignaturePacket s, KeyPacket signer, params ReadOnlyMemory<byte>[] parts)
    {
        try
        {
            return SignatureChecker.HasNoUnknownCritical(s) && SignatureEngine.VerifyDigest(signer, s, SignatureEngine.Digest(s, parts));
        }
        catch (PgpException)
        {
            return false;
        }
    }

    // The newest by creation time; of two made in the same second the later one in the packet order wins, as when a key is evaluated.
    private static SignaturePacket? Newest(IEnumerable<SignaturePacket> sigs)
    {
        SignaturePacket? best = null;
        foreach (SignaturePacket s in sigs)
        {
            if (best is null || (s.CreationTime ?? 0) >= (best.CreationTime ?? 0))
            {
                best = s;
            }
        }

        return best;
    }

    // The newest self-signature of this type over the parts that the primary key actually made; one that does not verify is not trusted to carry properties.
    private static SignaturePacket? NewestSelf(KeyWork w, IEnumerable<Packet> items, Func<SignaturePacket, bool> typeOk, params ReadOnlyMemory<byte>[] parts) =>
        Newest(items.OfType<SignaturePacket>().Where(s => typeOk(s) && Verifies(s, w.Primary, parts)));

    private static List<SignatureSubpacket> Inherit(SignaturePacket? from) =>
        from is null ? [] : from.HashedSubpackets.Where(s => !PerSignature.Contains(s.TypeId)).ToList();

    private static bool IsCertification(SignaturePacket s) =>
        s.Type is SignatureType.GenericCertification or SignatureType.PersonaCertification or SignatureType.CasualCertification or SignatureType.PositiveCertification;

    private static CryptoPolicy P(CryptoPolicy? p) => p ?? CryptoPolicy.Standard;

    private static KeyWork.UserWork FindUser(KeyWork w, string userId)
    {
        byte[] wanted = System.Text.Encoding.UTF8.GetBytes(userId);
        return w.Users.FirstOrDefault(u => u.Identity is UserIdPacket id && id.Value.Span.SequenceEqual(wanted))
            ?? throw new PgpException(PgpFailure.KeyCannotPerform, "The certificate has no such User ID.");
    }

    // ---- passwords ----

    /// <summary>
    /// Re-protects every secret key packet of <paramref name="cert"/>: each is unlocked with one of <paramref name="oldPasswords"/> (an unprotected packet needs none)
    /// and written again under <paramref name="newPassword"/>, or unprotected when that is null. Packets that carry no secret (a stripped key) are kept.
    /// Version 6 keys are protected with AEAD (OCB) and Argon2id, version 4 keys with AES-256 CFB and an iterated and salted SHA-256 S2K (RFC 9580 §3.7, §5.5.3).
    /// </summary>
    /// <exception cref="PgpException">A packet is protected and no old password opens it (<see cref="PgpFailure.KeyIsProtected"/>).</exception>
    public static PgpCertificate SetPassword(PgpCertificate cert, IReadOnlyList<byte[]> oldPasswords, byte[]? newPassword, CryptoPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(cert);
        ArgumentNullException.ThrowIfNull(oldPasswords);
        CryptoPolicy pol = P(policy);
        KeyWork w = KeyWork.From(cert.Transferable);
        PgpKey[] keys = [.. cert.Keys];
        w.Primary = Reprotect(keys[0], w.Primary, oldPasswords, newPassword, pol);
        for (int i = 0; i < w.Subs.Count; i++)
        {
            w.Subs[i].Key = Reprotect(keys[i + 1], w.Subs[i].Key, oldPasswords, newPassword, pol);
        }

        return w.ToCertificate();
    }

    private static KeyPacket Reprotect(PgpKey key, KeyPacket packet, IReadOnlyList<byte[]> oldPasswords, byte[]? newPassword, CryptoPolicy policy)
    {
        if (packet is not SecretKeyPacket)
        {
            return packet;
        }

        using PgpSecretKey unlocked = PgpSecretKey.Unlock(key, oldPasswords, policy.KdfLimits);
        return SecretKeyWriter.Rebuild(unlocked, newPassword ?? [], newPassword is not null, policy.KdfLimits);
    }

    // ---- user IDs ----

    /// <summary>
    /// Adds a User ID and certifies it with the primary key (type 0x13). The new certification carries the key flags, expiry and preferences of the key's
    /// newest self-signature. With <paramref name="makePrimary"/> the User ID is marked primary and the others are re-certified as not primary.
    /// </summary>
    /// <exception cref="PgpException">The User ID is already there, or the key is not the certificate's primary key.</exception>
    public static PgpCertificate AddUserId(PgpCertificate cert, PgpSecretKey primary, string userId, DateTimeOffset now, bool makePrimary = false, CryptoPolicy? policy = null)
    {
        RequireOwner(cert, primary);
        ArgumentException.ThrowIfNullOrEmpty(userId);
        CryptoPolicy pol = P(policy);
        KeyWork w = KeyWork.From(cert.Transferable);
        byte[] wanted = System.Text.Encoding.UTF8.GetBytes(userId);
        if (w.Users.Any(u => u.Identity is UserIdPacket id && id.Value.Span.SequenceEqual(wanted)))
        {
            throw new PgpException(PgpFailure.KeyCannotPerform, "The certificate already has this User ID.");
        }

        List<SignatureSubpacket> props = KeyProperties(w);
        Packet uid = Packet.Create((byte)PacketTag.UserId, wanted);
        var hashed = new List<SignatureSubpacket>(props);
        if (makePrimary)
        {
            hashed.Add(Subpackets.PrimaryUserId(true));
        }

        var user = new KeyWork.UserWork(uid);
        user.Items.Add(KeySignatures.Make(primary, SignatureType.PositiveCertification, hashed, now, pol, SignatureEngine.KeyInput(w.Primary), SignatureEngine.UserIdInput(uid)));
        w.Users.Add(user);
        PgpCertificate result = w.ToCertificate();
        return makePrimary ? SetPrimaryUserId(result, primary, userId, now, pol) : result;
    }

    // The properties a new certification inherits: those of the newest self-signature over the primary key or any of its User IDs.
    private static List<SignatureSubpacket> KeyProperties(KeyWork w)
    {
        byte[] pk = SignatureEngine.KeyInput(w.Primary);
        var candidates = new List<SignaturePacket>();
        if (NewestSelf(w, w.PrimaryItems, s => s.Type == SignatureType.DirectKey, pk) is { } d)
        {
            candidates.Add(d);
        }

        foreach (KeyWork.UserWork u in w.Users)
        {
            if (NewestSelf(w, u.Items, IsCertification, pk, SignatureEngine.UserIdInput(u.Identity)) is { } c)
            {
                candidates.Add(c);
            }
        }

        return Inherit(Newest(candidates));
    }

    /// <summary>Removes a User ID with its signatures. Other components are untouched.</summary>
    /// <exception cref="PgpException">There is no such User ID.</exception>
    public static PgpCertificate RemoveUserId(PgpCertificate cert, string userId)
    {
        ArgumentNullException.ThrowIfNull(cert);
        KeyWork w = KeyWork.From(cert.Transferable);
        w.Users.Remove(FindUser(w, userId));
        return w.ToCertificate();
    }

    /// <summary>
    /// Marks one User ID as the primary one: every User ID that has a valid self-certification gets a new one, with the primary flag set on the chosen
    /// User ID only (RFC 9580 §5.2.3.27). Their other properties carry over.
    /// </summary>
    public static PgpCertificate SetPrimaryUserId(PgpCertificate cert, PgpSecretKey primary, string userId, DateTimeOffset now, CryptoPolicy? policy = null)
    {
        RequireOwner(cert, primary);
        CryptoPolicy pol = P(policy);
        KeyWork w = KeyWork.From(cert.Transferable);
        KeyWork.UserWork chosen = FindUser(w, userId);
        byte[] pk = SignatureEngine.KeyInput(w.Primary);
        foreach (KeyWork.UserWork u in w.Users)
        {
            byte[] uidInput = SignatureEngine.UserIdInput(u.Identity);
            SignaturePacket? latest = NewestSelf(w, u.Items, IsCertification, pk, uidInput);
            if (latest is null && u != chosen)
            {
                continue;
            }

            List<SignatureSubpacket> hashed = latest is null ? KeyProperties(w) : Inherit(latest);
            hashed.Add(Subpackets.PrimaryUserId(u == chosen));
            u.Items.Add(KeySignatures.Make(primary, SignatureType.PositiveCertification, hashed, now, pol, pk, uidInput));
        }

        return w.ToCertificate();
    }

    // ---- self-signature updates ----

    /// <summary>
    /// Re-issues the self-signatures that carry a key's properties: for the primary key the direct-key signature (when there is one, and always for version 6)
    /// and one certification per User ID; for a subkey its binding signature. Each new signature starts from the newest valid one and applies
    /// <paramref name="change"/> to its subpackets, so unknown subpackets and the embedded back-signature of a signing subkey carry over.
    /// </summary>
    private static PgpCertificate UpdateSelfSignatures(PgpCertificate cert, PgpSecretKey primary, DateTimeOffset now, CryptoPolicy pol, Action<List<SignatureSubpacket>> change,
        byte[]? subkeyFingerprint)
    {
        RequireOwner(cert, primary);
        KeyWork w = KeyWork.From(cert.Transferable);
        byte[] pk = SignatureEngine.KeyInput(w.Primary);
        if (subkeyFingerprint is not null)
        {
            KeyWork.SubWork sub = w.Subs.FirstOrDefault(s => s.Key.GetFingerprint().AsSpan().SequenceEqual(subkeyFingerprint))
                ?? throw new PgpException(PgpFailure.KeyCannotPerform, "The certificate has no such subkey.");
            byte[] sk = SignatureEngine.KeyInput(sub.Key);
            SignaturePacket? latest = NewestSelf(w, sub.Items, s => s.Type == SignatureType.SubkeyBinding, pk, sk)
                ?? throw new PgpException(PgpFailure.KeyCannotPerform, "The subkey has no valid binding signature to renew.");
            List<SignatureSubpacket> hashed = Inherit(latest);
            change(hashed);
            // The back-signature of a signing subkey stays valid: it covers the same two keys, not the binding.
            var unhashed = latest.UnhashedSubpackets.Concat(latest.HashedSubpackets).Where(s => s.TypeId == (byte)SubpacketType.EmbeddedSignature).Take(1).ToList();
            sub.Items.Add(KeySignatures.MakeWith(primary, SignatureType.SubkeyBinding, hashed, unhashed, now, pol, pk, sk));
            return w.ToCertificate();
        }

        SignaturePacket? direct = NewestSelf(w, w.PrimaryItems, s => s.Type == SignatureType.DirectKey, pk);
        if (direct is not null || w.Primary.Version == 6)
        {
            List<SignatureSubpacket> hashed = direct is not null ? Inherit(direct) : KeyProperties(w);
            change(hashed);
            // RFC 9580 §5.2.3.10: a new direct-key signature supersedes the older ones; it goes after the existing direct signatures.
            int at = w.PrimaryItems.FindLastIndex(p => p is SignaturePacket) + 1;
            w.PrimaryItems.Insert(at, KeySignatures.Make(primary, SignatureType.DirectKey, hashed, now, pol, pk));
        }

        foreach (KeyWork.UserWork u in w.Users)
        {
            byte[] uidInput = SignatureEngine.UserIdInput(u.Identity);
            SignaturePacket? latest = NewestSelf(w, u.Items, IsCertification, pk, uidInput);
            if (latest is null)
            {
                continue;
            }

            List<SignatureSubpacket> hashed = Inherit(latest);
            if (latest.IsPrimaryUserId)
            {
                hashed.Add(Subpackets.PrimaryUserId(true));
            }

            change(hashed);
            u.Items.Add(KeySignatures.Make(primary, SignatureType.PositiveCertification, hashed, now, pol, pk, uidInput));
        }

        return w.ToCertificate();
    }

    private static void Replace(List<SignatureSubpacket> list, SignatureSubpacket replacement)
    {
        list.RemoveAll(s => s.TypeId == replacement.TypeId);
        list.Add(replacement);
    }

    /// <summary>
    /// Sets when a key expires. Pass null for no expiry. Without <paramref name="subkey"/> the primary key's self-signatures are re-issued (the expiry of the
    /// primary key bounds the whole certificate); with it, that subkey's binding signature is. The expiry is stored as seconds after the key was created (RFC 9580 §5.2.3.13).
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="expiresAt"/> is not after the key's creation.</exception>
    public static PgpCertificate SetExpiry(PgpCertificate cert, PgpSecretKey primary, DateTimeOffset? expiresAt, DateTimeOffset now, PgpKey? subkey = null, CryptoPolicy? policy = null)
    {
        RequireOwner(cert, primary);
        KeyPacket target = subkey?.Packet ?? cert.Primary.Packet;
        uint seconds = 0;
        if (expiresAt is { } e)
        {
            long delta = e.ToUnixTimeSeconds() - target.CreationTime;
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(delta, 0L, nameof(expiresAt));
            seconds = checked((uint)delta);
        }

        return UpdateSelfSignatures(cert, primary, now, P(policy), l => Replace(l, Subpackets.KeyExpiration(seconds)), subkey?.Fingerprint);
    }

    /// <summary>Sets the key flags of the primary key (without <paramref name="subkey"/>) or of one subkey (RFC 9580 §5.2.3.29).</summary>
    public static PgpCertificate SetKeyFlags(PgpCertificate cert, PgpSecretKey primary, PgpKeyUsage usage, DateTimeOffset now, PgpKey? subkey = null, CryptoPolicy? policy = null) =>
        UpdateSelfSignatures(cert, primary, now, P(policy), l => Replace(l, Subpackets.KeyFlags(usage)), subkey?.Fingerprint);

    /// <summary>Sets the algorithm preferences and features the primary key's self-signatures advertise. Members that are null stay as they are.</summary>
    public static PgpCertificate SetPreferences(PgpCertificate cert, PgpSecretKey primary, PgpKeyPreferences preferences, DateTimeOffset now, CryptoPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(preferences);
        return UpdateSelfSignatures(cert, primary, now, P(policy), l =>
        {
            if (preferences.Symmetric is { } sym)
            {
                Replace(l, SignatureSubpacket.Create((byte)SubpacketType.PreferredSymmetricAlgorithms, false, sym.Select(x => (byte)x).ToArray()));
            }

            if (preferences.Hash is { } hash)
            {
                Replace(l, SignatureSubpacket.Create((byte)SubpacketType.PreferredHashAlgorithms, false, hash.Select(x => (byte)x).ToArray()));
            }

            if (preferences.Compression is { } comp)
            {
                Replace(l, SignatureSubpacket.Create((byte)SubpacketType.PreferredCompressionAlgorithms, false, comp.Select(x => (byte)x).ToArray()));
            }

            if (preferences.AeadSuites is { } suites)
            {
                Replace(l, SignatureSubpacket.Create((byte)SubpacketType.PreferredAeadCiphersuites, false, suites.SelectMany(x => new[] { (byte)x.Cipher, (byte)x.Aead }).ToArray()));
            }

            if (preferences.Features is { } f)
            {
                Replace(l, Subpackets.Features(f));
            }
        }, null);
    }

    /// <summary>
    /// Brings a certificate's self-signatures up to date (the work of <c>sop update-key</c>): re-issues them at <paramref name="now"/>, removes
    /// preferences that name weak algorithms (MD5, SHA-1, RIPEMD-160, the old ciphers), and drops unknown Features bits. Unless <paramref name="noAddedCapabilities"/>
    /// is set, advertises the features and AEAD suites this library supports. The primary key is never changed. When the certificate has
    /// no usable encryption subkey and <paramref name="signingOnly"/> is false, one is added.
    /// </summary>
    public static PgpCertificate Refresh(PgpCertificate cert, PgpSecretKey primary, DateTimeOffset now, bool signingOnly, bool noAddedCapabilities, CryptoPolicy? policy = null)
    {
        CryptoPolicy pol = P(policy);
        PgpCertificate result = UpdateSelfSignatures(cert, primary, now, pol, l =>
        {
            Prune(l, (byte)SubpacketType.PreferredHashAlgorithms, b => b is (byte)PgpHashAlgorithm.Md5 or (byte)PgpHashAlgorithm.Sha1 or (byte)PgpHashAlgorithm.Ripemd160);
            Prune(l, (byte)SubpacketType.PreferredSymmetricAlgorithms, b => b is not ((byte)SymmetricAlgorithm.Aes128 or (byte)SymmetricAlgorithm.Aes192 or (byte)SymmetricAlgorithm.Aes256));
            if (l.Find(s => s.TypeId == (byte)SubpacketType.Features) is { Data.Length: > 0 } feat)
            {
                byte kept = (byte)(feat.Data.Span[0] & 0x09);
                if (!noAddedCapabilities && cert.Primary.Packet.Version == 6)
                {
                    kept |= 0x09;
                }

                Replace(l, Subpackets.Features(kept));
            }
            else if (!noAddedCapabilities)
            {
                Replace(l, Subpackets.Features(0x09));
            }
        }, null);

        if (!signingOnly && cert.Keys.Skip(1).All(k => !k.StateAt(now).IsValid || (k.StateAt(now).Usage & (PgpKeyUsage.EncryptCommunications | PgpKeyUsage.EncryptStorage)) == 0))
        {
            result = AddSubkey(result, primary, PgpSubkeyKind.Encryption, now, null, policy: pol);
        }

        return result;
    }

    private static void Prune(List<SignatureSubpacket> l, byte type, Func<byte, bool> drop)
    {
        SignatureSubpacket? s = l.Find(x => x.TypeId == type);
        if (s is null)
        {
            return;
        }

        l.Remove(s);
        byte[] kept = s.Data.ToArray().Where(b => !drop(b)).ToArray();
        if (kept.Length > 0)
        {
            l.Add(SignatureSubpacket.Create(type, s.IsCritical, kept));
        }
    }

    // ---- subkeys ----

    /// <summary>
    /// Generates a subkey of the primary key's algorithm family and binds it (type 0x18). A signing subkey also carries the embedded primary key binding signature
    /// it makes over the two keys (RFC 9580 §5.2.1.8). The new subkey is written unprotected unless <paramref name="password"/> is given.
    /// </summary>
    public static PgpCertificate AddSubkey(PgpCertificate cert, PgpSecretKey primary, PgpSubkeyKind kind, DateTimeOffset now, DateTimeOffset? expiresAt, byte[]? password = null, CryptoPolicy? policy = null)
    {
        RequireOwner(cert, primary);
        CryptoPolicy pol = P(policy);
        KeyWork w = KeyWork.From(cert.Transferable);
        PgpKeyGenerator.KeyKind generated = SubkeyKind(w.Primary, kind);
        PgpKeyGenerator.NewKey sub = PgpKeyGenerator.NewKey.Create(generated, w.Primary.Version, PgpTime.ToSeconds(now), subkey: true);
        byte[] pk = SignatureEngine.KeyInput(w.Primary);
        byte[] sk = SignatureEngine.KeyInput(sub.Public);
        PgpKeyUsage usage = kind switch
        {
            PgpSubkeyKind.Encryption => PgpKeyUsage.EncryptCommunications | PgpKeyUsage.EncryptStorage,
            PgpSubkeyKind.Signing => PgpKeyUsage.Sign,
            _ => PgpKeyUsage.Authenticate,
        };
        var hashed = new List<SignatureSubpacket> { Subpackets.KeyFlags(usage) };
        if (expiresAt is { } e)
        {
            long delta = e.ToUnixTimeSeconds() - sub.Public.CreationTime;
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(delta, 0L, nameof(expiresAt));
            hashed.Add(Subpackets.KeyExpiration(checked((uint)delta)));
        }

        var unhashed = new List<SignatureSubpacket>();
        if (kind is PgpSubkeyKind.Signing)
        {
            // The subkey, unlocked for a moment, signs the primary key it is bound to.
            SecretKeyPacket plain = SecretKeyWriter.Build(sub.Public, sub.Secret, [], protect: false);
            PgpCertificate tmp = PgpCertificate.FromTransferable(TransferableKey.Parse([w.Primary, plain]));
            using PgpSecretKey subSecret = PgpSecretKey.Unlock(tmp.Keys[1]);
            SignaturePacket back = KeySignatures.Make(subSecret, SignatureType.PrimaryKeyBinding, [], now, pol, pk, sk);
            unhashed.Add(Subpackets.EmbeddedSignature(back));
        }

        var work = new KeyWork.SubWork(SecretKeyWriter.Build(sub.Public, sub.Secret, password ?? [], password is not null));
        work.Items.Add(KeySignatures.MakeWith(primary, SignatureType.SubkeyBinding, hashed, unhashed, now, pol, pk, sk));
        w.Subs.Add(work);
        CryptographicOperations.ZeroMemory(sub.Secret);
        return w.ToCertificate();
    }

    private static PgpKeyGenerator.KeyKind SubkeyKind(KeyPacket primary, PgpSubkeyKind kind)
    {
        bool enc = kind == PgpSubkeyKind.Encryption;
        switch (primary.Algorithm)
        {
            case PublicKeyAlgorithm.Ed25519:
                return enc ? PgpKeyGenerator.KeyKind.X25519 : PgpKeyGenerator.KeyKind.Ed25519;
            case PublicKeyAlgorithm.Ed448:
                return enc ? PgpKeyGenerator.KeyKind.X448 : PgpKeyGenerator.KeyKind.Ed448;
            case PublicKeyAlgorithm.EdDsaLegacy:
                return enc ? PgpKeyGenerator.KeyKind.EcdhCurve25519 : PgpKeyGenerator.KeyKind.EdDsaLegacy;
            case PublicKeyAlgorithm.Rsa or PublicKeyAlgorithm.RsaSignOnly:
                return PgpKeyGenerator.KeyKind.Rsa3072;
            case PublicKeyAlgorithm.Ecdsa:
                {
                    ReadOnlySpan<byte> oid = primary.Material.CurveOid.Span;
                    SignatureEngine.Curves.TryFind(oid, out int size);
                    return size switch
                    {
                        48 => enc ? PgpKeyGenerator.KeyKind.EcdhP384 : PgpKeyGenerator.KeyKind.EcdsaP384,
                        66 => enc ? PgpKeyGenerator.KeyKind.EcdhP521 : PgpKeyGenerator.KeyKind.EcdsaP521,
                        _ => enc ? PgpKeyGenerator.KeyKind.EcdhP256 : PgpKeyGenerator.KeyKind.EcdsaP256,
                    };
                }

            case PublicKeyAlgorithm.MlDsa65Ed25519:
                return enc ? PgpKeyGenerator.KeyKind.MlKem768X25519 : PgpKeyGenerator.KeyKind.MlDsa65Ed25519;
            case PublicKeyAlgorithm.MlDsa87Ed448:
                return enc ? PgpKeyGenerator.KeyKind.MlKem1024X448 : PgpKeyGenerator.KeyKind.MlDsa87Ed448;
            default:
                throw new PgpException(PgpFailure.Unsupported, $"No subkey is generated for a primary key of algorithm {(byte)primary.Algorithm}.");
        }
    }

    /// <summary>Removes a subkey with its signatures.</summary>
    /// <exception cref="PgpException">There is no subkey with this fingerprint.</exception>
    public static PgpCertificate RemoveSubkey(PgpCertificate cert, ReadOnlySpan<byte> fingerprint)
    {
        ArgumentNullException.ThrowIfNull(cert);
        byte[] fp = fingerprint.ToArray();
        KeyWork w = KeyWork.From(cert.Transferable);
        int i = w.Subs.FindIndex(s => s.Key.GetFingerprint().AsSpan().SequenceEqual(fp));
        if (i < 0)
        {
            throw new PgpException(PgpFailure.KeyCannotPerform, "The certificate has no such subkey.");
        }

        w.Subs.RemoveAt(i);
        return w.ToCertificate();
    }

    // ---- revocation ----

    /// <summary>
    /// Revokes the whole key with a key revocation signature (type 0x20, RFC 9580 §5.2.1.9). <see cref="PgpRevocationReason.None"/> and
    /// <see cref="PgpRevocationReason.Compromised"/> are hard revocations (the key is invalid at every time); the others only take effect from <paramref name="now"/>.
    /// </summary>
    public static PgpCertificate RevokeKey(PgpCertificate cert, PgpSecretKey primary, PgpRevocationReason reason, string text, DateTimeOffset now, CryptoPolicy? policy = null)
    {
        RequireOwner(cert, primary);
        KeyWork w = KeyWork.From(cert.Transferable);
        int at = w.PrimaryItems.FindLastIndex(p => p is SignaturePacket) + 1;
        w.PrimaryItems.Insert(at, KeySignatures.Make(primary, SignatureType.KeyRevocation, [Subpackets.Revocation((byte)reason, text ?? string.Empty)], now, P(policy), SignatureEngine.KeyInput(w.Primary)));
        return w.ToCertificate();
    }

    /// <summary>Revokes one subkey with a subkey revocation signature (type 0x28).</summary>
    public static PgpCertificate RevokeSubkey(PgpCertificate cert, PgpSecretKey primary, ReadOnlySpan<byte> subkeyFingerprint, PgpRevocationReason reason, string text, DateTimeOffset now, CryptoPolicy? policy = null)
    {
        RequireOwner(cert, primary);
        byte[] fp = subkeyFingerprint.ToArray();
        KeyWork w = KeyWork.From(cert.Transferable);
        KeyWork.SubWork sub = w.Subs.FirstOrDefault(s => s.Key.GetFingerprint().AsSpan().SequenceEqual(fp))
            ?? throw new PgpException(PgpFailure.KeyCannotPerform, "The certificate has no such subkey.");
        sub.Items.Add(KeySignatures.Make(primary, SignatureType.SubkeyRevocation, [Subpackets.Revocation((byte)reason, text ?? string.Empty)], now, P(policy),
            SignatureEngine.KeyInput(w.Primary), SignatureEngine.KeyInput(sub.Key)));
        return w.ToCertificate();
    }

    /// <summary>Revokes the primary key's own certification of a User ID (type 0x30).</summary>
    public static PgpCertificate RevokeUserId(PgpCertificate cert, PgpSecretKey primary, string userId, PgpRevocationReason reason, string text, DateTimeOffset now, CryptoPolicy? policy = null)
    {
        RequireOwner(cert, primary);
        KeyWork w = KeyWork.From(cert.Transferable);
        KeyWork.UserWork u = FindUser(w, userId);
        u.Items.Add(KeySignatures.Make(primary, SignatureType.CertificationRevocation, [Subpackets.Revocation((byte)reason, text ?? string.Empty)], now, P(policy),
            SignatureEngine.KeyInput(w.Primary), SignatureEngine.UserIdInput(u.Identity)));
        return w.ToCertificate();
    }

    /// <summary>
    /// A stand-alone revocation certificate (RFC 9580 §10.1.2): the public primary key followed by a key revocation signature, nothing else. Merge it into
    /// the certificate (or publish it) when the key must be revoked.
    /// </summary>
    public static PgpCertificate CreateRevocationCertificate(PgpCertificate cert, PgpSecretKey primary, PgpRevocationReason reason, string text, DateTimeOffset now, CryptoPolicy? policy = null)
    {
        RequireOwner(cert, primary);
        KeyPacket pub = cert.Primary.Packet is SecretKeyPacket sk ? sk.ToPublic() : cert.Primary.Packet;
        SignaturePacket sig = KeySignatures.Make(primary, SignatureType.KeyRevocation, [Subpackets.Revocation((byte)reason, text ?? string.Empty)], now, P(policy), SignatureEngine.KeyInput(pub));
        return PgpCertificate.FromTransferable(TransferableKey.Parse([pub, sig]));
    }

    // ---- certification ----

    /// <summary>
    /// Adds a third-party certification of a User ID, made by <paramref name="certifier"/> (RFC 9580 §5.2.1.3, §10.1). The User ID must be on the certificate
    /// with a valid self-signature unless <paramref name="requireSelfSignature"/> is false, in which case it is added first and certified without one.
    /// </summary>
    /// <exception cref="PgpException">The User ID is not on the certificate (<see cref="PgpFailure.KeyCannotPerform"/>), or the key cannot certify.</exception>
    public static PgpCertificate Certify(PgpCertificate target, string userId, PgpSecretKey certifier, DateTimeOffset now, PgpCertificationOptions? options = null,
        bool requireSelfSignature = true, CryptoPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(certifier);
        ArgumentException.ThrowIfNullOrEmpty(userId);
        options ??= new PgpCertificationOptions();
        KeyWork w = KeyWork.From(target.Transferable);
        byte[] wanted = System.Text.Encoding.UTF8.GetBytes(userId);
        KeyWork.UserWork? u = w.Users.FirstOrDefault(x => x.Identity is UserIdPacket id && id.Value.Span.SequenceEqual(wanted));
        byte[] pk = SignatureEngine.KeyInput(w.Primary);
        if (u is not null && requireSelfSignature && NewestSelf(w, u.Items, IsCertification, pk, SignatureEngine.UserIdInput(u.Identity)) is null)
        {
            u = null;
        }

        if (u is null)
        {
            if (requireSelfSignature)
            {
                throw new PgpException(PgpFailure.KeyCannotPerform, "The certificate has no self-signed User ID with this text.");
            }

            u = new KeyWork.UserWork(Packet.Create((byte)PacketTag.UserId, wanted));
            w.Users.Add(u);
        }

        var hashed = new List<SignatureSubpacket>();
        if (options.TrustLevel is { } tl)
        {
            hashed.Add(SignatureSubpacket.Create((byte)SubpacketType.TrustSignature, false, new[] { tl, options.TrustAmount }));
            if (options.Regex is { } re)
            {
                hashed.Add(SignatureSubpacket.Create((byte)SubpacketType.RegularExpression, false, System.Text.Encoding.UTF8.GetBytes(re).Append((byte)0).ToArray()));
            }
        }

        if (!options.Exportable)
        {
            hashed.Add(SignatureSubpacket.Create((byte)SubpacketType.ExportableCertification, false, new byte[] { 0 }));
        }

        if (!options.Revocable)
        {
            hashed.Add(SignatureSubpacket.Create((byte)SubpacketType.Revocable, false, new byte[] { 0 }));
        }

        if (options.ValidFor is { } v)
        {
            byte[] b = new byte[4];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(b, checked((uint)v.TotalSeconds));
            hashed.Add(SignatureSubpacket.Create((byte)SubpacketType.SignatureExpirationTime, false, b));
        }

        // the key is framed by the version of the signature, which is the certifier key's (RFC 9580 §5.2.4)
        u.Items.Add(KeySignatures.Make(certifier, (SignatureType)options.Level, hashed, now, P(policy), SignatureEngine.KeyInput(w.Primary, certifier.Key.Packet.Version), SignatureEngine.UserIdInput(u.Identity)));
        return w.ToCertificate();
    }

    /// <summary>Revokes a certification the <paramref name="certifier"/> made earlier (type 0x30 by the certifier's key).</summary>
    public static PgpCertificate RevokeCertification(PgpCertificate target, string userId, PgpSecretKey certifier, PgpRevocationReason reason, string text, DateTimeOffset now, CryptoPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(certifier);
        KeyWork w = KeyWork.From(target.Transferable);
        KeyWork.UserWork u = FindUser(w, userId);
        u.Items.Add(KeySignatures.Make(certifier, SignatureType.CertificationRevocation, [Subpackets.Revocation((byte)reason, text ?? string.Empty)], now, P(policy),
            SignatureEngine.KeyInput(w.Primary, certifier.Key.Packet.Version), SignatureEngine.UserIdInput(u.Identity)));
        return w.ToCertificate();
    }

    // ---- merge ----

    /// <summary>
    /// Merges two copies of the same certificate: User IDs and subkeys the first lacks are added, and signatures the first lacks are added after the ones it has.
    /// Packets already present are kept as they are and nothing is dropped. Trust packets are local to one keyring and are not copied.
    /// A signature whose issuer is the primary key and that does not verify is left out.
    /// </summary>
    /// <exception cref="PgpException">The certificates have different primary keys.</exception>
    public static PgpCertificate Merge(PgpCertificate a, PgpCertificate b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);
        if (!a.Primary.Fingerprint.AsSpan().SequenceEqual(b.Primary.Fingerprint))
        {
            throw new PgpException(PgpFailure.KeyCannotPerform, "The certificates have different primary keys.");
        }

        KeyWork w = KeyWork.From(a.Transferable);
        KeyWork o = KeyWork.From(b.Transferable);
        byte[] pk = SignatureEngine.KeyInput(w.Primary);

        // A secret copy that the other side only has as a certificate stays secret; a certificate merged into by a secret key gains no secrets.
        MergeItems(w.PrimaryItems, o.PrimaryItems, w.Primary, pk);
        foreach (KeyWork.UserWork ou in o.Users)
        {
            KeyWork.UserWork? mine = w.Users.FirstOrDefault(u => u.Identity.Body.Span.SequenceEqual(ou.Identity.Body.Span) && u.Identity.TagId == ou.Identity.TagId);
            if (mine is null)
            {
                mine = new KeyWork.UserWork(ou.Identity);
                w.Users.Add(mine);
            }

            MergeItems(mine.Items, ou.Items, w.Primary, pk, SignatureEngine.UserIdInput(ou.Identity));
        }

        foreach (KeyWork.SubWork os in o.Subs)
        {
            KeyWork.SubWork? mine = w.Subs.FirstOrDefault(s => s.Key.GetFingerprint().AsSpan().SequenceEqual(os.Key.GetFingerprint()));
            if (mine is null)
            {
                mine = new KeyWork.SubWork(os.Key is SecretKeyPacket sp ? sp.ToPublic() : os.Key);
                w.Subs.Add(mine);
            }

            MergeItems(mine.Items, os.Items, w.Primary, pk, SignatureEngine.KeyInput(os.Key));
        }

        return w.ToCertificate();
    }

    /// <summary>
    /// Adds a stand-alone revocation signature (the form GnuPG writes for a revocation certificate: the signature packet without the key) to the certificate it
    /// belongs to. A key revocation (type 0x20) must verify against the primary key; a subkey revocation (type 0x28) against the primary key over the matching subkey.
    /// </summary>
    /// <returns>The certificate with the signature added; the same certificate if it already holds the signature.</returns>
    /// <exception cref="PgpException">The signature is not a revocation of this certificate or does not verify.</exception>
    public static PgpCertificate AddRevocationSignature(PgpCertificate cert, SignaturePacket revocation)
    {
        ArgumentNullException.ThrowIfNull(cert);
        ArgumentNullException.ThrowIfNull(revocation);
        KeyWork w = KeyWork.From(cert.Transferable);
        byte[] pk = SignatureEngine.KeyInput(w.Primary);
        List<Packet> target;
        if (revocation.Type == SignatureType.KeyRevocation && Verifies(revocation, w.Primary, pk))
        {
            target = w.PrimaryItems;
        }
        else if (revocation.Type == SignatureType.SubkeyRevocation)
        {
            KeyWork.SubWork? sub = w.Subs.FirstOrDefault(x => Verifies(revocation, w.Primary, pk, SignatureEngine.KeyInput(x.Key)));
            target = sub?.Items ?? throw new PgpException(PgpFailure.KeyCannotPerform, "The revocation does not match a subkey of this certificate.");
        }
        else
        {
            throw new PgpException(PgpFailure.KeyCannotPerform, "The signature is not a revocation that verifies for this certificate.");
        }

        if (target.Any(p => p.TagId == revocation.TagId && p.Body.Span.SequenceEqual(revocation.Body.Span)))
        {
            return cert;
        }

        target.Add(revocation);
        return w.ToCertificate();
    }

    private static void MergeItems(List<Packet> mine, List<Packet> theirs, KeyPacket primary, byte[] pk, byte[]? extra = null)
    {
        foreach (Packet p in theirs)
        {
            if (p is TrustPacket)
            {
                continue;
            }

            bool have = mine.Any(m => m.TagId == p.TagId && m.Body.Span.SequenceEqual(p.Body.Span));
            if (have)
            {
                continue;
            }

            if (p is SignaturePacket s && IssuedBy(s, primary) && !Verifies(s, primary, extra is null ? new ReadOnlyMemory<byte>[] { pk } : new ReadOnlyMemory<byte>[] { pk, extra }))
            {
                continue;
            }

            mine.Add(p);
        }
    }

    internal static bool IssuedBy(SignaturePacket s, KeyPacket key) =>
        s.IssuerFingerprint is { } fp ? fp.Length > 1 && fp.Span[1..].SequenceEqual(key.GetFingerprint())
            : s.IssuerKeyId is { } id && id.Span.SequenceEqual(key.GetKeyId());
}
