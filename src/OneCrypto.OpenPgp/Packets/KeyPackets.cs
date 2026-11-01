using System.Buffers.Binary;
using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.OpenPgp.Packets;

/// <summary>
/// The fields every key packet starts with (RFC 9580 §5.5.2; LibrePGP §5.5.2): version, creation time, algorithm and the public key
/// material. Public Key, Public Subkey, Secret Key and Secret Subkey packets all derive from it. Versions 2 and 3 (read only), 4, 5
/// (LibrePGP, read only) and 6 are decoded; any other version makes the whole packet an <see cref="UnrecognizedPacket"/>.
/// </summary>
public abstract class KeyPacket : Packet
{
    private byte[]? _fingerprint;

    internal KeyPacket(byte tagId, ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded, KeyFields fields)
        : base(tagId, body, header, encoded)
    {
        Version = fields.Version;
        CreationTime = fields.CreationTime;
        ExpirationDays = fields.ExpirationDays;
        Algorithm = fields.Algorithm;
        Material = fields.Material;
        PublicBody = fields.PublicBody;
    }

    /// <summary>The key version: 2 or 3 (read only), 4, 5 (LibrePGP, read only) or 6.</summary>
    public byte Version { get; }

    /// <summary>The creation time in seconds since 1970-01-01 UTC.</summary>
    public uint CreationTime { get; }

    /// <summary>For a version 2 or 3 key: the validity period in days, 0 for none. Zero for later versions, which keep expiry in signatures.</summary>
    public ushort ExpirationDays { get; }

    /// <summary>The public-key algorithm.</summary>
    public PublicKeyAlgorithm Algorithm { get; }

    /// <summary>The public key material.</summary>
    public PublicKeyMaterial Material { get; }

    /// <summary>The octets of the public key packet body: for a secret key, the part before the secret-key fields. This is what the fingerprint covers.</summary>
    public ReadOnlyMemory<byte> PublicBody { get; }

    /// <summary>True for a subkey packet (tags 7 and 14).</summary>
    public bool IsSubkey => TagId is (byte)PacketTag.PublicSubkey or (byte)PacketTag.SecretSubkey;

    /// <summary>True for a secret key packet (tags 5 and 7).</summary>
    public bool IsSecret => TagId is (byte)PacketTag.SecretKey or (byte)PacketTag.SecretSubkey;

    /// <summary>
    /// The fingerprint (RFC 9580 §5.5.4): MD5 of the RSA values for a v2/v3 key (16 octets), SHA-1 over 0x99, a two-octet length and the public
    /// body for v4 (20 octets), SHA-256 over 0x9A (v5) or 0x9B (v6), a four-octet length and the public body (32 octets).
    /// </summary>
    /// <returns>A copy of the fingerprint octets.</returns>
    public byte[] GetFingerprint() => (byte[])(_fingerprint ??= ComputeFingerprint()).Clone();

    /// <summary>The key ID (RFC 9580 §5.5.4): the low 64 bits of the modulus for v3, the low 64 bits of the fingerprint for v4, the high 64 bits for v5 and v6.</summary>
    /// <returns>Eight octets.</returns>
    public byte[] GetKeyId()
    {
        byte[] id = new byte[8];
        if (Version <= 3)
        {
            ReadOnlySpan<byte> n = Material.Values.Count > 0 ? Material.Values[0].Span : default;
            if (n.Length >= 8)
            {
                n[^8..].CopyTo(id);
            }
            else
            {
                n.CopyTo(id.AsSpan(8 - n.Length));
            }

            return id;
        }

        byte[] fp = _fingerprint ??= ComputeFingerprint();
        (Version == 4 ? fp.AsSpan(fp.Length - 8, 8) : fp.AsSpan(0, 8)).CopyTo(id);
        return id;
    }

    /// <summary>The fingerprint as upper-case hexadecimal.</summary>
    public string FingerprintHex => Convert.ToHexString(_fingerprint ??= ComputeFingerprint());

    /// <summary>The key ID as upper-case hexadecimal.</summary>
    public string KeyIdHex => Convert.ToHexString(GetKeyId());

    private byte[] ComputeFingerprint()
    {
        ReadOnlySpan<byte> body = PublicBody.Span;
        switch (Version)
        {
            case 2:
            case 3:
                {
                    // RFC 9580 §5.5.4: v3 hashes the RSA modulus and exponent without their bit counts. MD5 is fixed by the format here.
#pragma warning disable CA5351 // The version 3 fingerprint is defined as MD5 over the RSA values (RFC 9580 §5.5.4); it names a key, it protects nothing.
                    using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
#pragma warning restore CA5351
                    foreach (ReadOnlyMemory<byte> v in Material.Values)
                    {
                        md5.AppendData(v.Span);
                    }

                    return md5.GetHashAndReset();
                }

            case 4:
                {
                    byte[] input = new byte[3 + body.Length];
                    input[0] = 0x99;
                    BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(1), checked((ushort)body.Length));
                    body.CopyTo(input.AsSpan(3));
#pragma warning disable CA5350 // The version 4 fingerprint is defined as SHA-1 over the key (RFC 9580 §5.5.4); it names a key, it protects nothing.
                    return SHA1.HashData(input);
#pragma warning restore CA5350
                }

            default:
                {
                    byte[] input = new byte[5 + body.Length];
                    input[0] = Version == 5 ? (byte)0x9A : (byte)0x9B;
                    BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(1), (uint)body.Length);
                    body.CopyTo(input.AsSpan(5));
                    return SHA256.HashData(input);
                }
        }
    }

    internal readonly record struct KeyFields(byte Version, uint CreationTime, ushort ExpirationDays, PublicKeyAlgorithm Algorithm,
        PublicKeyMaterial Material, ReadOnlyMemory<byte> PublicBody, int PublicLength);

    /// <summary>Reads the public part of a key packet body. Returns null when the version is not one this layer decodes.</summary>
    internal static KeyFields? ReadPublicPart(ReadOnlyMemory<byte> body, bool secret, OpenPgpLimits limits)
    {
        var c = new PacketCursor(body);
        byte version = c.Byte("key version");
        if (version is < 2 or > 6)
        {
            return null;
        }

        uint time = c.U32("key creation time");
        ushort days = 0;
        if (version <= 3)
        {
            days = c.U16("key validity days");
        }

        var algorithm = (PublicKeyAlgorithm)c.Byte("key algorithm");
        PublicKeyMaterial material;
        if (version >= 5)
        {
            // RFC 9580 §5.5.2: v6 (and LibrePGP v5) carry a four-octet count of the material, so an unknown algorithm can be skipped.
            ReadOnlyMemory<byte> counted = c.TakeCounted32("public key material");
            material = PublicKeyMaterial.Parse(algorithm, counted, true, limits.MaxMpiBits, out int used);
            if (used != counted.Length)
            {
                throw c.Fail(OpenPgpError.InvalidField, "public key material length");
            }
        }
        else
        {
            // Without the count, the material of a public key is the rest of the packet; in a secret key it must be parsed to find its end.
            material = PublicKeyMaterial.Parse(algorithm, c.Remaining == 0 ? default : body[c.Position..], !secret, limits.MaxMpiBits, out int used);
            if (!secret && used != c.Remaining)
            {
                throw new OpenPgpParseException(OpenPgpError.TrailingData, c.Offset + used, "public key material");
            }

            c.Take(used, "public key material");
        }

        return new KeyFields(version, time, days, algorithm, material, body[..c.Position], c.Position);
    }
}

/// <summary>Public Key and Public Subkey packets (RFC 9580 §5.5.1.1, §5.5.1.2).</summary>
public sealed class PublicKeyPacket : KeyPacket
{
    internal PublicKeyPacket(byte tagId, ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded, KeyFields fields)
        : base(tagId, body, header, encoded, fields)
    {
    }

    /// <summary>Creates a v4 or v6 public key packet from its parts.</summary>
    /// <param name="version">4 or 6.</param>
    /// <param name="creationTime">Seconds since 1970-01-01 UTC.</param>
    /// <param name="algorithm">The algorithm.</param>
    /// <param name="material">The material octets as stored (MPIs with their bit counts, OID with its length, or the fixed-size strings).</param>
    /// <param name="subkey">True for a Public Subkey packet.</param>
    /// <exception cref="OpenPgpParseException">The material does not parse for the algorithm.</exception>
    public static PublicKeyPacket Create(byte version, uint creationTime, PublicKeyAlgorithm algorithm, ReadOnlyMemory<byte> material, bool subkey = false)
    {
        if (version is not (4 or 6))
        {
            throw new ArgumentOutOfRangeException(nameof(version), "Only version 4 and 6 keys are written.");
        }

        byte[] body = new byte[6 + (version == 6 ? 4 : 0) + material.Length];
        body[0] = version;
        BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(1), creationTime);
        body[5] = (byte)algorithm;
        int at = 6;
        if (version == 6)
        {
            BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(6), (uint)material.Length);
            at = 10;
        }

        material.Span.CopyTo(body.AsSpan(at));
        return (PublicKeyPacket)Packet.Create(subkey ? (byte)PacketTag.PublicSubkey : (byte)PacketTag.PublicKey, body);
    }
}

/// <summary>
/// How a secret key packet's secret fields are protected (RFC 9580 §5.5.3): the S2K usage octet and the parameters it brings.
/// </summary>
public sealed class SecretKeyProtection
{
    internal SecretKeyProtection(byte usage, SymmetricAlgorithm cipher, AeadAlgorithm? aead, S2kSpecifier? s2k, ReadOnlyMemory<byte> iv, ReadOnlyMemory<byte> parameters)
    {
        Usage = usage;
        Cipher = cipher;
        Aead = aead;
        S2k = s2k;
        Iv = iv;
        Parameters = parameters;
    }

    /// <summary>The S2K usage octet: 0 not protected, 253 AEAD, 254 CFB with a SHA-1 check, 255 CFB with a checksum, anything else a cipher ID with an implicit MD5 key.</summary>
    public byte Usage { get; }

    /// <summary>True when the secret fields are encrypted.</summary>
    public bool IsProtected => Usage != 0;

    /// <summary>The cipher, when the secret fields are encrypted.</summary>
    public SymmetricAlgorithm Cipher { get; }

    /// <summary>The AEAD algorithm, when usage is 253.</summary>
    public AeadAlgorithm? Aead { get; }

    /// <summary>The string-to-key specifier; null when not protected or when the legacy implicit MD5 key is used.</summary>
    public S2kSpecifier? S2k { get; }

    /// <summary>The initialisation vector or AEAD nonce; empty when not protected.</summary>
    public ReadOnlyMemory<byte> Iv { get; }

    /// <summary>The conditional parameter octets as stored (cipher, AEAD, S2K length and S2K, IV), which the AEAD associated data and a lossless write need; empty when not protected.</summary>
    public ReadOnlyMemory<byte> Parameters { get; }
}

/// <summary>
/// Secret Key and Secret Subkey packets (RFC 9580 §5.5.1.3, §5.5.1.4). The public part is decoded as for a public key; the secret fields are
/// described by <see cref="Protection"/> and kept as octets in <see cref="SecretData"/>. Decrypting them is the job of the layer above.
/// </summary>
public sealed class SecretKeyPacket : KeyPacket
{
    internal SecretKeyPacket(byte tagId, ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded, KeyFields fields,
        SecretKeyProtection protection, ReadOnlyMemory<byte> secretData)
        : base(tagId, body, header, encoded, fields)
    {
        Protection = protection;
        SecretData = secretData;
    }

    /// <summary>The protection parameters.</summary>
    public SecretKeyProtection Protection { get; }

    /// <summary>
    /// The secret key data as stored: the algorithm-specific secret values followed by a two-octet checksum (usage 0 for v3/v4, and 255) or,
    /// when encrypted, the ciphertext with its trailing SHA-1 (254) or AEAD tag (253).
    /// </summary>
    public ReadOnlyMemory<byte> SecretData { get; }

    /// <summary>The corresponding Public Key (or Public Subkey) packet, with the secret fields removed. Needed to extract a certificate from a key.</summary>
    public PublicKeyPacket ToPublic()
    {
        byte tag = IsSubkey ? (byte)PacketTag.PublicSubkey : (byte)PacketTag.PublicKey;
        return (PublicKeyPacket)Packet.Create(tag, PublicBody);
    }

    internal static SecretKeyPacket Parse(byte tagId, ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded, KeyFields fields, OpenPgpLimits limits)
    {
        _ = limits;
        var c = new PacketCursor(body, 0);
        c.Take(fields.PublicLength, "public part");
        byte usage = c.Byte("s2k usage");
        byte version = fields.Version;
        SymmetricAlgorithm cipher = SymmetricAlgorithm.Plaintext;
        AeadAlgorithm? aead = null;
        S2kSpecifier? s2k = null;
        ReadOnlyMemory<byte> iv = default;
        ReadOnlyMemory<byte> parameters = default;
        if (usage != 0)
        {
            if (version >= 5)
            {
                // RFC 9580 §5.5.3: a one-octet count of all the conditional parameter fields that follow.
                byte count = c.Byte("s2k parameter count");
                parameters = c.Take(count, "s2k parameters");
                var q = new PacketCursor(parameters, c.Offset);
                if (usage is 253 or 254 or 255)
                {
                    cipher = (SymmetricAlgorithm)q.Byte("cipher");
                    if (usage == 253)
                    {
                        aead = (AeadAlgorithm)q.Byte("aead");
                    }

                    // v6 has a one-octet S2K length for 253 and 254; LibrePGP v5 implies the length from the S2K type.
                    if (version == 6)
                    {
                        byte s2kLength = q.Byte("s2k length");
                        s2k = S2kSpecifier.Read(ref q, s2kLength);
                    }
                    else
                    {
                        s2k = S2kSpecifier.Read(ref q, null);
                    }
                }
                else
                {
                    cipher = (SymmetricAlgorithm)usage;
                }

                iv = q.Rest();
            }
            else
            {
                int start = c.Position;
                if (usage is 253 or 254 or 255)
                {
                    cipher = (SymmetricAlgorithm)c.Byte("cipher");
                    if (usage == 253)
                    {
                        aead = (AeadAlgorithm)c.Byte("aead");
                    }

                    s2k = S2kSpecifier.Read(ref c, null);
                }
                else
                {
                    cipher = (SymmetricAlgorithm)usage;
                }

                int ivLength = usage == 253 ? AeadNonceLength(aead!.Value) : CfbBlockSize(cipher);
                if (ivLength <= 0)
                {
                    throw c.Fail(OpenPgpError.InvalidField, "unknown cipher or AEAD for the s2k IV");
                }

                iv = c.Take(ivLength, "s2k iv");
                parameters = body.Slice(start, c.Position - start);
            }
        }

        ReadOnlyMemory<byte> secret;
        if (version == 5)
        {
            // LibrePGP §5.5.3: a four-octet count of the secret material precedes it.
            secret = c.TakeCounted32("secret key material");
            if (!c.AtEnd)
            {
                throw c.Fail(OpenPgpError.TrailingData, "secret key material");
            }
        }
        else
        {
            secret = c.Rest();
        }

        return new SecretKeyPacket(tagId, body, header, encoded, fields, new SecretKeyProtection(usage, cipher, aead, s2k, iv, parameters), secret);
    }

    private static int CfbBlockSize(SymmetricAlgorithm cipher) => cipher switch
    {
        SymmetricAlgorithm.Idea or SymmetricAlgorithm.TripleDes or SymmetricAlgorithm.Cast5 or SymmetricAlgorithm.Blowfish => 8,
        SymmetricAlgorithm.Aes128 or SymmetricAlgorithm.Aes192 or SymmetricAlgorithm.Aes256 or SymmetricAlgorithm.Twofish
            or SymmetricAlgorithm.Camellia128 or SymmetricAlgorithm.Camellia192 or SymmetricAlgorithm.Camellia256 => 16,
        _ => 0,
    };

    internal static int AeadNonceLength(AeadAlgorithm aead) => aead switch
    {
        AeadAlgorithm.Eax => 16,
        AeadAlgorithm.Ocb => 15,
        AeadAlgorithm.Gcm => 12,
        _ => 0,
    };
}
