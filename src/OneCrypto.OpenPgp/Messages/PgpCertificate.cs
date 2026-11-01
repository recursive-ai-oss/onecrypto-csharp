using System.Security.Cryptography;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>What a key may be used for, from its Key Flags subpacket (RFC 9580 §5.2.3.29).</summary>
[Flags]
public enum PgpKeyUsage
{
    /// <summary>No usage.</summary>
    None = 0,

    /// <summary>Certify other keys.</summary>
    Certify = 1,

    /// <summary>Sign data.</summary>
    Sign = 2,

    /// <summary>Encrypt communications.</summary>
    EncryptCommunications = 4,

    /// <summary>Encrypt storage.</summary>
    EncryptStorage = 8,

    /// <summary>Authenticate.</summary>
    Authenticate = 0x20,
}

/// <summary>The state of a key at one instant: whether it is bound, unexpired and unrevoked, and what it may do.</summary>
/// <param name="IsValid">True when the key is bound to its certificate, already created, not expired and not revoked at the reference time.</param>
/// <param name="Reason">Why the key is not valid, or null.</param>
/// <param name="Usage">The key flags in force from the newest valid binding or self-signature that carries them.</param>
/// <param name="ExpiresAt">When the key expires, or null if it does not.</param>
public sealed record PgpKeyState(bool IsValid, string? Reason, PgpKeyUsage Usage, DateTimeOffset? ExpiresAt);

/// <summary>One key packet of a certificate, the primary key or a subkey, with the signatures that bind it.</summary>
public sealed class PgpKey
{
    private readonly object _gate = new();
    private IReadOnlyList<SignaturePacket>? _bindings;
    private IReadOnlyList<SignaturePacket>? _revocations;
    private readonly Dictionary<SignaturePacket, List<SignaturePacket>> _uidRevocations = [];
    private readonly Dictionary<SignaturePacket, SignaturePacket> _backSignatures = [];
    private readonly HashSet<SignaturePacket> _fromUserId = [];

    internal PgpKey(PgpCertificate certificate, KeyPacket packet, bool isPrimary, IReadOnlyList<SignaturePacket> signatures)
    {
        Certificate = certificate;
        Packet = packet;
        IsPrimary = isPrimary;
        Signatures = signatures;
    }

    /// <summary>The certificate this key belongs to.</summary>
    public PgpCertificate Certificate { get; }

    /// <summary>The key packet as read.</summary>
    public KeyPacket Packet { get; }

    /// <summary>True for the primary key.</summary>
    public bool IsPrimary { get; }

    internal IReadOnlyList<SignaturePacket> Signatures { get; }

    /// <summary>The fingerprint (20 octets for v4, 32 for v6).</summary>
    public byte[] Fingerprint => Packet.GetFingerprint();

    /// <summary>The eight-octet key ID.</summary>
    public byte[] KeyId => Packet.GetKeyId();

    /// <summary>The public-key algorithm.</summary>
    public PublicKeyAlgorithm Algorithm => Packet.Algorithm;

    // RFC 9580 §5.2.3.12: issuer subpackets are hints. A binding is judged by whether the primary key verifies it, so a wrong or foreign
    // hint neither makes a good binding fail nor makes a bad one pass. A critical subpacket we do not understand voids the signature (§5.2.3.7).
    private static bool Usable(SignaturePacket s) => SignatureChecker.HasNoUnknownCritical(s);

    private static bool Verifies(SignaturePacket s, KeyPacket signer, params ReadOnlyMemory<byte>[] parts)
    {
        try
        {
            return SignatureEngine.VerifyDigest(signer, s, SignatureEngine.Digest(s, parts));
        }
        catch (PgpException)
        {
            return false;
        }
    }

    /// <summary>RFC 9580 §10.1: the signatures that bind this key and carry its flags and expiry, already verified by the primary key.</summary>
    private IReadOnlyList<SignaturePacket> Bindings()
    {
        lock (_gate)
        {
            if (_bindings is not null)
            {
                return _bindings;
            }

            KeyPacket primary = Certificate.Primary.Packet;
            byte[] pk = SignatureEngine.KeyInput(primary);
            var good = new List<SignaturePacket>();
            if (IsPrimary)
            {
                foreach (SignaturePacket s in Certificate.Transferable.DirectSignatures)
                {
                    if (s.Type == SignatureType.DirectKey && Usable(s) && Verifies(s, primary, pk))
                    {
                        good.Add(s);
                    }
                }

                foreach (UserComponent u in Certificate.Transferable.Users)
                {
                    byte[] uid = SignatureEngine.UserIdInput(u.Identity);
                    var revs = new List<SignaturePacket>();
                    var certs = new List<SignaturePacket>();
                    foreach (SignaturePacket s in u.Signatures)
                    {
                        if (s.Type is SignatureType.GenericCertification or SignatureType.PersonaCertification or SignatureType.CasualCertification or SignatureType.PositiveCertification
                            && Usable(s) && Verifies(s, primary, pk, uid))
                        {
                            certs.Add(s);
                        }
                        else if (s.Type == SignatureType.CertificationRevocation && Usable(s) && Verifies(s, primary, pk, uid))
                        {
                            revs.Add(s);
                        }
                    }

                    foreach (SignaturePacket c in certs)
                    {
                        good.Add(c);
                        _fromUserId.Add(c);
                        _uidRevocations[c] = revs;
                    }
                }
            }
            else
            {
                byte[] sk = SignatureEngine.KeyInput(Packet);
                foreach (SignaturePacket s in Signatures)
                {
                    if (s.Type != SignatureType.SubkeyBinding || !Usable(s) || !Verifies(s, primary, pk, sk))
                    {
                        continue;
                    }

                    // RFC 9580 §5.2.1.8 / §10.1: a signing-capable subkey proves it consents with an embedded primary key binding signature made by the subkey.
                    bool signs = s.KeyFlags is { Length: > 0 } f && (f.Span[0] & 2) != 0;
                    if (signs)
                    {
                        SignaturePacket? back = s.EmbeddedSignatures.FirstOrDefault(e => e.Type == SignatureType.PrimaryKeyBinding && Usable(e) && Verifies(e, Packet, pk, sk));
                        if (back is null)
                        {
                            continue;
                        }

                        _backSignatures[s] = back;
                    }

                    good.Add(s);
                }
            }

            _bindings = good;
            return good;
        }
    }

    private IReadOnlyList<SignaturePacket> Revocations()
    {
        lock (_gate)
        {
            if (_revocations is not null)
            {
                return _revocations;
            }

            KeyPacket primary = Certificate.Primary.Packet;
            byte[] pk = SignatureEngine.KeyInput(primary);
            var good = new List<SignaturePacket>();
            if (IsPrimary)
            {
                foreach (SignaturePacket s in Certificate.Transferable.DirectSignatures)
                {
                    if (s.Type == SignatureType.KeyRevocation && Usable(s) && Verifies(s, primary, pk))
                    {
                        good.Add(s);
                    }
                }
            }
            else
            {
                byte[] sk = SignatureEngine.KeyInput(Packet);
                foreach (SignaturePacket s in Signatures)
                {
                    if (s.Type == SignatureType.SubkeyRevocation && Usable(s) && Verifies(s, primary, pk, sk))
                    {
                        good.Add(s);
                    }
                }
            }

            _revocations = good;
            return good;
        }
    }

    private static bool ExpiredAt(SignaturePacket s, long at) => s.ExpirationSeconds is { } e and > 0 && (long)(s.CreationTime ?? 0) + e <= at;

    // RFC 9580 §5.2.3.31: no reason, "key is compromised" and any code we do not know are hard revocations, which invalidate the key at every time;
    // superseded, retired and "user ID no longer valid" only take effect from the moment they were made.
    private static bool IsHardRevocation(SignaturePacket r) => r.ReasonForRevocation is not { Code: 1 or 3 or 32 };

    /// <summary>
    /// Evaluates the key at <paramref name="at"/>: created, bound by its newest valid self-signature then in force, not expired, not revoked.
    /// A soft revocation made later than <paramref name="at"/> does not count, so old signatures stay good; a hard one does (RFC 9580 §5.2.3.31).
    /// Binding signatures and revocations that have themselves expired by then are ignored, as are bindings of a user ID revoked since, and subkey
    /// bindings whose primary key binding signature has expired.
    /// </summary>
    public PgpKeyState StateAt(DateTimeOffset at)
    {
        DateTimeOffset created = DateTimeOffset.FromUnixTimeSeconds(Packet.CreationTime);
        if (at < created)
        {
            return new PgpKeyState(false, "The key did not exist yet at the reference time.", PgpKeyUsage.None, null);
        }

        if (!IsPrimary && !Certificate.Primary.StateAt(at).IsValid)
        {
            return new PgpKeyState(false, "The primary key is not valid at the reference time.", PgpKeyUsage.None, null);
        }

        long now = at.ToUnixTimeSeconds();
        var eligible = new List<SignaturePacket>();
        foreach (SignaturePacket s in Bindings())
        {
            long t = s.CreationTime ?? 0;
            if (t > now || ExpiredAt(s, now))
            {
                continue;
            }

            if (_uidRevocations.TryGetValue(s, out List<SignaturePacket>? revs) && revs.Any(r => (r.CreationTime ?? 0) >= t && (r.CreationTime ?? 0) <= now && !ExpiredAt(r, now)))
            {
                continue;
            }

            if (_backSignatures.TryGetValue(s, out SignaturePacket? back) && ExpiredAt(back, now))
            {
                continue;
            }

            eligible.Add(s);
        }

        if (eligible.Count == 0)
        {
            return new PgpKeyState(false, IsPrimary ? "No valid self-signature binds the primary key." : "No valid binding signature binds the subkey.", PgpKeyUsage.None, null);
        }

        // RFC 9580 §5.2.3.19: when a user ID is marked primary, the other user IDs do not decide the key's flags or expiry.
        bool primaryUidMarked = eligible.Any(x => _fromUserId.Contains(x) && x.IsPrimaryUserId);
        PgpKeyUsage? usage = null;
        uint? expiry = null;
        long newestFlagTime = -1;
        long newestExpiryTime = -1;
        foreach (SignaturePacket s in eligible)
        {
            if (primaryUidMarked && _fromUserId.Contains(s) && !s.IsPrimaryUserId)
            {
                continue;
            }

            long t = s.CreationTime ?? 0;
            if (s.KeyFlags is { } f && t >= newestFlagTime)
            {
                // An empty Key Flags subpacket says the key may do nothing.
                usage = f.Length > 0 ? (PgpKeyUsage)(f.Span[0] & 0x2F) : PgpKeyUsage.None;
                newestFlagTime = t;
            }

            if (t >= newestExpiryTime && (s.KeyFlags is not null || s.KeyExpirationSeconds is not null || IsPrimary))
            {
                expiry = s.KeyExpirationSeconds;
                newestExpiryTime = t;
            }
        }

        foreach (SignaturePacket r in Revocations())
        {
            long rt = r.CreationTime ?? 0;
            if (rt <= now && ExpiredAt(r, now))
            {
                continue;
            }

            if (rt <= now || IsHardRevocation(r))
            {
                return new PgpKeyState(false, "The key is revoked.", PgpKeyUsage.None, null);
            }
        }

        DateTimeOffset? expires = expiry is { } e and > 0 ? created.AddSeconds(e) : null;
        usage ??= InferUsage(Packet.Algorithm);
        if (expires is { } x && at >= x)
        {
            return new PgpKeyState(false, "The key has expired.", usage.Value, expires);
        }

        return new PgpKeyState(true, null, usage.Value, expires);
    }

    private static PgpKeyUsage InferUsage(PublicKeyAlgorithm a) => a switch
    {
        PublicKeyAlgorithm.Rsa => PgpKeyUsage.Certify | PgpKeyUsage.Sign | PgpKeyUsage.EncryptCommunications | PgpKeyUsage.EncryptStorage,
        PublicKeyAlgorithm.RsaSignOnly or PublicKeyAlgorithm.Dsa or PublicKeyAlgorithm.Ecdsa or PublicKeyAlgorithm.EdDsaLegacy or PublicKeyAlgorithm.Ed25519 or PublicKeyAlgorithm.Ed448 =>
            PgpKeyUsage.Certify | PgpKeyUsage.Sign,
        _ => PgpKeyUsage.EncryptCommunications | PgpKeyUsage.EncryptStorage,
    };

    /// <summary>The Features octet of the newest valid self-signature (RFC 9580 §5.2.3.32): bit 0x01 SEIPD v1, 0x08 SEIPD v2. Zero when absent.</summary>
    internal byte Features(DateTimeOffset at)
    {
        byte result = 0;
        long newest = -1;
        foreach (SignaturePacket s in Certificate.Primary.Bindings().Concat(Bindings()))
        {
            long t = s.CreationTime ?? 0;
            if (t <= at.ToUnixTimeSeconds() && t >= newest && s.Features is { Length: > 0 } f)
            {
                result = f.Span[0];
                newest = t;
            }
        }

        return result;
    }

    /// <summary>The newest valid self-signature's preferred AEAD ciphersuites (RFC 9580 §5.2.3.15), as pairs of cipher and AEAD identifiers.</summary>
    internal ReadOnlyMemory<byte> PreferredAeadSuites(DateTimeOffset at)
    {
        ReadOnlyMemory<byte> result = default;
        long newest = -1;
        foreach (SignaturePacket s in Certificate.Primary.Bindings().Concat(Bindings()))
        {
            long t = s.CreationTime ?? 0;
            if (t <= at.ToUnixTimeSeconds() && t >= newest && s.PreferredAeadCiphersuites is { } p)
            {
                result = p;
                newest = t;
            }
        }

        return result;
    }
}

/// <summary>
/// An OpenPGP certificate (Transferable Public Key, RFC 9580 §10.1), possibly with secret key material: the primary key and subkeys with their binding
/// data, over a lossless <see cref="TransferableKey"/>. Binding is checked lazily and against the reference time you ask about.
/// </summary>
public sealed class PgpCertificate
{
    private PgpCertificate(TransferableKey key)
    {
        Transferable = key;
        var all = new List<PgpKey>();
        Primary = new PgpKey(this, key.Primary, true, key.DirectSignatures);
        all.Add(Primary);
        foreach (SubkeyComponent s in key.Subkeys)
        {
            all.Add(new PgpKey(this, s.Key, false, s.Signatures));
        }

        Keys = all;
    }

    /// <summary>The underlying packets.</summary>
    public TransferableKey Transferable { get; }

    /// <summary>The primary key.</summary>
    public PgpKey Primary { get; }

    /// <summary>The primary key then the subkeys, in file order.</summary>
    public IReadOnlyList<PgpKey> Keys { get; }

    /// <summary>The User ID texts, in file order.</summary>
    public IEnumerable<string> UserIds => Transferable.Users.Where(u => u.Identity is UserIdPacket).Select(u => ((UserIdPacket)u.Identity).Text);

    /// <summary>The fingerprint of the primary key.</summary>
    public byte[] Fingerprint => Primary.Fingerprint;

    /// <summary>True when the certificate carries secret key packets.</summary>
    public bool HasSecretKeyMaterial => Transferable.IsSecret;

    /// <summary>Wraps a parsed transferable key.</summary>
    public static PgpCertificate FromTransferable(TransferableKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return new PgpCertificate(key);
    }

    /// <summary>Parses the first certificate in binary or ASCII-armored data.</summary>
    /// <exception cref="OpenPgpParseException">The data is not a well-formed key.</exception>
    public static PgpCertificate Parse(ReadOnlyMemory<byte> data)
    {
        IReadOnlyList<PgpCertificate> all = ParseAll(data);
        return all.Count > 0 ? all[0] : throw new OpenPgpParseException(OpenPgpError.Truncated, 0, "no key");
    }

    /// <summary>Parses every certificate in binary or ASCII-armored data (armor blocks may be concatenated).</summary>
    /// <exception cref="OpenPgpParseException">The data is not a well-formed key ring.</exception>
    public static IReadOnlyList<PgpCertificate> ParseAll(ReadOnlyMemory<byte> data)
    {
        var result = new List<PgpCertificate>();
        foreach (byte[] block in PgpFormat.Unarmor(data))
        {
            foreach (TransferableKey k in TransferableKey.ParseAll(PacketParser.ParseAll(block)))
            {
                result.Add(new PgpCertificate(k));
            }
        }

        return result;
    }

    /// <summary>Finds the key whose fingerprint or key ID matches, or null.</summary>
    public PgpKey? FindKey(ReadOnlySpan<byte> fingerprintOrKeyId)
    {
        foreach (PgpKey k in Keys)
        {
            if (fingerprintOrKeyId.Length == 8 ? fingerprintOrKeyId.SequenceEqual(k.KeyId) : fingerprintOrKeyId.SequenceEqual(k.Fingerprint))
            {
                return k;
            }
        }

        return null;
    }

    /// <summary>The newest key that is valid at <paramref name="at"/> and may sign, or null.</summary>
    public PgpKey? FindSigningKey(DateTimeOffset at)
    {
        PgpKey? best = null;
        foreach (PgpKey k in Keys)
        {
            PgpKeyState st = k.StateAt(at);
            bool algOk = k.Algorithm is PublicKeyAlgorithm.Rsa or PublicKeyAlgorithm.RsaSignOnly or PublicKeyAlgorithm.Ecdsa or PublicKeyAlgorithm.EdDsaLegacy or PublicKeyAlgorithm.Ed25519 or PublicKeyAlgorithm.Ed448;
            if (st.IsValid && algOk && (st.Usage & PgpKeyUsage.Sign) != 0 && (best is null || k.Packet.CreationTime > best.Packet.CreationTime))
            {
                best = k;
            }
        }

        return best;
    }

    /// <summary>The public form of this certificate, written as binary packets.</summary>
    public byte[] ExportPublic()
    {
        using var ms = new MemoryStream();
        Transferable.ToPublic().WriteTo(ms);
        return ms.ToArray();
    }
}

/// <summary>Armor handling shared by the message layer: detects armored input and decodes concatenated blocks.</summary>
internal static class PgpFormat
{
    internal static IEnumerable<byte[]> Unarmor(ReadOnlyMemory<byte> data)
    {
        if (data.IsEmpty)
        {
            yield break;
        }

        if (!Armor.LooksArmored(data.Span[0]))
        {
            yield return data.ToArray();
            yield break;
        }

        yield return Armor.Decode(data.Span, ArmorReadOptions.Lenient).Data;
    }
}

/// <summary>The set of conversions between <see cref="DateTimeOffset"/> and OpenPGP's four-octet times.</summary>
internal static class PgpTime
{
    internal static uint ToSeconds(DateTimeOffset t) => (uint)t.ToUnixTimeSeconds();

    internal static byte[] FourOctets(DateTimeOffset t)
    {
        byte[] b = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(b, ToSeconds(t));
        return b;
    }
}
