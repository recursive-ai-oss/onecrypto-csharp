namespace RecursiveAI.OneCrypto.OpenPgp.Packets;

/// <summary>A User ID or User Attribute packet of a transferable key with the signatures that follow it (RFC 9580 §10.1).</summary>
public sealed class UserComponent
{
    internal UserComponent(Packet identity)
    {
        Identity = identity;
    }

    /// <summary>The <see cref="UserIdPacket"/> or <see cref="UserAttributePacket"/>.</summary>
    public Packet Identity { get; }

    /// <summary>The certifications and revocations that follow it, in order.</summary>
    public IReadOnlyList<SignaturePacket> Signatures => SignatureList;

    /// <summary>Every packet that follows the identity before the next component and is not a signature (trust packets, markers, unknown packets), in order.</summary>
    public IReadOnlyList<Packet> OtherPackets => OtherList;

    internal List<SignaturePacket> SignatureList { get; } = [];

    internal List<Packet> OtherList { get; } = [];
}

/// <summary>A subkey packet of a transferable key with the signatures that follow it (RFC 9580 §10.1).</summary>
public sealed class SubkeyComponent
{
    internal SubkeyComponent(KeyPacket key)
    {
        Key = key;
    }

    /// <summary>The Public Subkey or Secret Subkey packet.</summary>
    public KeyPacket Key { get; }

    /// <summary>The binding signatures and revocations that follow it, in order.</summary>
    public IReadOnlyList<SignaturePacket> Signatures => SignatureList;

    /// <summary>Every packet that follows the subkey before the next component and is not a signature, in order.</summary>
    public IReadOnlyList<Packet> OtherPackets => OtherList;

    internal List<SignaturePacket> SignatureList { get; } = [];

    internal List<Packet> OtherList { get; } = [];
}

/// <summary>
/// A Transferable Public Key or Transferable Secret Key (RFC 9580 §10.1, §10.2) as a lossless model: the primary key, its direct
/// signatures, its User IDs and subkeys with their signatures. <see cref="Packets"/> holds every packet in input order, so writing the key
/// back reproduces the input exactly. Nothing is validated cryptographically, and signatures are grouped by position only.
/// </summary>
public sealed class TransferableKey
{
    private TransferableKey(IReadOnlyList<Packet> packets, KeyPacket primary, List<SignaturePacket> direct, List<Packet> primaryOther,
        List<UserComponent> users, List<SubkeyComponent> subkeys)
    {
        Packets = packets;
        Primary = primary;
        DirectSignatures = direct;
        PrimaryOtherPackets = primaryOther;
        Users = users;
        Subkeys = subkeys;
    }

    /// <summary>Every packet of the key in order.</summary>
    public IReadOnlyList<Packet> Packets { get; }

    /// <summary>The primary Public Key or Secret Key packet.</summary>
    public KeyPacket Primary { get; }

    /// <summary>True for a Transferable Secret Key.</summary>
    public bool IsSecret => Primary.IsSecret;

    /// <summary>The signatures between the primary key and the first User ID or subkey (direct key signatures and key revocations).</summary>
    public IReadOnlyList<SignaturePacket> DirectSignatures { get; }

    /// <summary>Non-signature packets between the primary key and the first User ID or subkey.</summary>
    public IReadOnlyList<Packet> PrimaryOtherPackets { get; }

    /// <summary>The User IDs and User Attributes, in order.</summary>
    public IReadOnlyList<UserComponent> Users { get; }

    /// <summary>The subkeys, in order.</summary>
    public IReadOnlyList<SubkeyComponent> Subkeys { get; }

    /// <summary>Splits a packet sequence into transferable keys: each Public Key or Secret Key packet starts a new one.</summary>
    /// <param name="packets">The packets, for example from <see cref="PacketParser.ParseAll(ReadOnlyMemory{byte}, OpenPgpLimits?)"/>.</param>
    /// <returns>The keys in order; empty for no packets.</returns>
    /// <exception cref="OpenPgpParseException">The first packet is not a primary key, a public and a secret packet are mixed within one key, or a packet other than a User ID, User Attribute or subkey component starts a component in the wrong place.</exception>
    public static IReadOnlyList<TransferableKey> ParseAll(IReadOnlyList<Packet> packets)
    {
        ArgumentNullException.ThrowIfNull(packets);
        var keys = new List<TransferableKey>();
        int start = 0;
        for (int i = 1; i <= packets.Count; i++)
        {
            if (i == packets.Count || packets[i].TagId is (byte)PacketTag.PublicKey or (byte)PacketTag.SecretKey)
            {
                keys.Add(Build(packets, start, i));
                start = i;
            }
        }

        if (packets.Count == 0)
        {
            keys.Clear();
        }

        return keys;
    }

    /// <summary>Reads exactly one transferable key.</summary>
    /// <param name="packets">The packets of one key.</param>
    /// <exception cref="OpenPgpParseException">There is not exactly one well-formed key.</exception>
    public static TransferableKey Parse(IReadOnlyList<Packet> packets)
    {
        IReadOnlyList<TransferableKey> keys = ParseAll(packets);
        if (keys.Count != 1)
        {
            throw new OpenPgpParseException(OpenPgpError.InvalidStructure, 0, keys.Count == 0 ? "no key" : "more than one key");
        }

        return keys[0];
    }

    /// <summary>Writes the key's packets, as read unless <paramref name="canonical"/> is set.</summary>
    /// <param name="destination">Where to write.</param>
    /// <param name="canonical">True to re-encode every header canonically.</param>
    public void WriteTo(Stream destination, bool canonical = false) => PacketParser.Write(Packets, destination, canonical);

    /// <summary>
    /// The Transferable Public Key for this key: secret key and subkey packets become public ones, and trust packets (which are local to one
    /// keyring) are dropped. Signatures and everything else are kept as read. A key that is already public is returned as it is.
    /// </summary>
    public TransferableKey ToPublic()
    {
        if (!IsSecret)
        {
            return this;
        }

        var converted = new List<Packet>(Packets.Count);
        foreach (Packet p in Packets)
        {
            if (p is SecretKeyPacket sk)
            {
                converted.Add(sk.ToPublic());
            }
            else if (p is not TrustPacket)
            {
                converted.Add(p);
            }
        }

        return Parse(converted);
    }

    private static TransferableKey Build(IReadOnlyList<Packet> all, int start, int end)
    {
        if (all[start] is not KeyPacket { IsSubkey: false } primary)
        {
            throw new OpenPgpParseException(OpenPgpError.InvalidStructure, 0, "a transferable key starts with a primary key packet");
        }

        var direct = new List<SignaturePacket>();
        var primaryOther = new List<Packet>();
        var users = new List<UserComponent>();
        var subkeys = new List<SubkeyComponent>();
        UserComponent? user = null;
        SubkeyComponent? subkey = null;
        for (int i = start + 1; i < end; i++)
        {
            Packet p = all[i];
            switch (p)
            {
                case UserIdPacket or UserAttributePacket:
                    if (subkey is not null)
                    {
                        throw new OpenPgpParseException(OpenPgpError.InvalidStructure, 0, "a User ID follows a subkey");
                    }

                    user = new UserComponent(p);
                    users.Add(user);
                    break;
                case KeyPacket { IsSubkey: true } sub:
                    if (sub.IsSecret != primary.IsSecret)
                    {
                        throw new OpenPgpParseException(OpenPgpError.InvalidStructure, 0, "public and secret key packets are mixed");
                    }

                    subkey = new SubkeyComponent(sub);
                    subkeys.Add(subkey);
                    user = null;
                    break;
                case KeyPacket:
                    throw new OpenPgpParseException(OpenPgpError.InvalidStructure, 0, "a second primary key");
                case SignaturePacket sig:
                    if (subkey is not null)
                    {
                        subkey.SignatureList.Add(sig);
                    }
                    else if (user is not null)
                    {
                        user.SignatureList.Add(sig);
                    }
                    else
                    {
                        direct.Add(sig);
                    }

                    break;
                default:
                    if (subkey is not null)
                    {
                        subkey.OtherList.Add(p);
                    }
                    else if (user is not null)
                    {
                        user.OtherList.Add(p);
                    }
                    else
                    {
                        primaryOther.Add(p);
                    }

                    break;
            }
        }

        var slice = new List<Packet>(end - start);
        for (int i = start; i < end; i++)
        {
            slice.Add(all[i]);
        }

        return new TransferableKey(slice, primary, direct, primaryOther, users, subkeys);
    }
}
