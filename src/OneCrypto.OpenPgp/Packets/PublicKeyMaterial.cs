namespace RecursiveAI.OneCrypto.OpenPgp.Packets;

/// <summary>
/// The algorithm-specific part of a public key (RFC 9580 §5.5.5, RFC 9980 §4.3.2, §5.3.2, §6.2.2): the octets as stored and the values split
/// out of them. Values are slices of the packet body, with MPI length prefixes removed. For an algorithm this layer does not know, only
/// <see cref="Raw"/> is set.
/// </summary>
public sealed class PublicKeyMaterial
{
    internal PublicKeyMaterial(PublicKeyAlgorithm algorithm, ReadOnlyMemory<byte> raw, IReadOnlyList<ReadOnlyMemory<byte>> values,
        ReadOnlyMemory<byte> curveOid, ReadOnlyMemory<byte> kdfParameters, bool known)
    {
        Algorithm = algorithm;
        Raw = raw;
        Values = values;
        CurveOid = curveOid;
        KdfParameters = kdfParameters;
        IsKnown = known;
    }

    /// <summary>The algorithm.</summary>
    public PublicKeyAlgorithm Algorithm { get; }

    /// <summary>The octets exactly as stored, MPI bit counts and OID length included.</summary>
    public ReadOnlyMemory<byte> Raw { get; }

    /// <summary>False when the algorithm is one this layer cannot split; <see cref="Values"/> is empty then.</summary>
    public bool IsKnown { get; }

    /// <summary>
    /// The values in the order the specification lists them, without length prefixes: RSA n, e; DSA p, q, g, y; Elgamal p, g, y; ECDSA, EdDSALegacy and ECDH the
    /// point; X25519, X448, Ed25519, Ed448 the key; the post-quantum combinations the traditional key then the post-quantum key.
    /// </summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> Values { get; }

    /// <summary>The curve OID octets (without the length octet) for ECDSA, EdDSALegacy, ECDH and LibrePGP Kyber; empty otherwise.</summary>
    public ReadOnlyMemory<byte> CurveOid { get; }

    /// <summary>For ECDH (RFC 9580 §5.5.5.6): the KDF parameter octets after the length octet (reserved 0x01, hash ID, symmetric ID); empty otherwise.</summary>
    public ReadOnlyMemory<byte> KdfParameters { get; }

    /// <summary>
    /// Reads the material that starts a key packet's algorithm-specific part.
    /// </summary>
    /// <param name="algorithm">The algorithm.</param>
    /// <param name="data">The octets starting at the material; may continue past it (secret key data) when <paramref name="exactLength"/> is false.</param>
    /// <param name="exactLength">True when <paramref name="data"/> is exactly the material, as when a v5/v6 count is given: an unknown algorithm is then kept opaque.</param>
    /// <param name="maxMpiBits">The longest MPI to accept.</param>
    /// <param name="length">The number of octets the material takes.</param>
    /// <exception cref="OpenPgpParseException">The material is malformed, or the algorithm is unknown and its length cannot be told.</exception>
    public static PublicKeyMaterial Parse(PublicKeyAlgorithm algorithm, ReadOnlyMemory<byte> data, bool exactLength, int maxMpiBits, out int length)
    {
        // A curve we do not know may come with an encoding of its own. When the material is the whole of the data, anything that does not parse
        // as the standard layout is kept as opaque bytes, so a certificate holding such a key still loads (RFC 9580 §5.5.5.6, §5.5.5.8).
        if (exactLength && algorithm is PublicKeyAlgorithm.Ecdsa or PublicKeyAlgorithm.EdDsaLegacy or PublicKeyAlgorithm.Ecdh)
        {
            try
            {
                PublicKeyMaterial m = ParseCore(algorithm, data, exactLength, maxMpiBits, out length);
                if (length == data.Length)
                {
                    return m;
                }
            }
            catch (OpenPgpParseException)
            {
            }

            length = data.Length;
            return new PublicKeyMaterial(algorithm, data, [], default, default, false);
        }

        return ParseCore(algorithm, data, exactLength, maxMpiBits, out length);
    }

    private static PublicKeyMaterial ParseCore(PublicKeyAlgorithm algorithm, ReadOnlyMemory<byte> data, bool exactLength, int maxMpiBits, out int length)
    {
        var c = new PacketCursor(data);
        var values = new List<ReadOnlyMemory<byte>>(4);
        ReadOnlyMemory<byte> oid = default;
        ReadOnlyMemory<byte> kdf = default;
        switch (algorithm)
        {
            case PublicKeyAlgorithm.Rsa:
            case PublicKeyAlgorithm.RsaEncryptOnly:
            case PublicKeyAlgorithm.RsaSignOnly:
                values.Add(c.Mpi("rsa n", maxMpiBits));
                values.Add(c.Mpi("rsa e", maxMpiBits));
                break;
            case PublicKeyAlgorithm.Dsa:
                values.Add(c.Mpi("dsa p", maxMpiBits));
                values.Add(c.Mpi("dsa q", maxMpiBits));
                values.Add(c.Mpi("dsa g", maxMpiBits));
                values.Add(c.Mpi("dsa y", maxMpiBits));
                break;
            case PublicKeyAlgorithm.ElGamal:
                values.Add(c.Mpi("elgamal p", maxMpiBits));
                values.Add(c.Mpi("elgamal g", maxMpiBits));
                values.Add(c.Mpi("elgamal y", maxMpiBits));
                break;
            case PublicKeyAlgorithm.Ecdsa:
            case PublicKeyAlgorithm.EdDsaLegacy:
                oid = ReadOid(ref c);
                values.Add(c.Mpi("ec point", maxMpiBits));
                break;
            case PublicKeyAlgorithm.Ecdh:
                oid = ReadOid(ref c);
                values.Add(c.Mpi("ec point", maxMpiBits));
                byte kdfLength = c.Byte("ecdh kdf length");
                if (kdfLength != 3)
                {
                    throw c.Fail(OpenPgpError.InvalidField, "ecdh kdf parameters");
                }

                kdf = c.Take(kdfLength, "ecdh kdf parameters");
                if (kdf.Span[0] != 1)
                {
                    throw c.Fail(OpenPgpError.InvalidField, "ecdh kdf reserved octet");
                }

                break;
            case PublicKeyAlgorithm.LibrePgpKyber:
                oid = ReadOid(ref c);
                values.Add(c.Mpi("ec point", maxMpiBits));
                values.Add(c.TakeCounted32("kyber public key"));
                break;
            default:
                if (FixedSizes(algorithm) is { } sizes)
                {
                    foreach (int size in sizes)
                    {
                        values.Add(c.Take(size, "public key"));
                    }

                    break;
                }

                if (!exactLength)
                {
                    throw c.Fail(OpenPgpError.InvalidField, "unknown public-key algorithm " + (byte)algorithm);
                }

                length = data.Length;
                return new PublicKeyMaterial(algorithm, data, [], default, default, false);
        }

        length = c.Position;
        return new PublicKeyMaterial(algorithm, data[..length], values, oid, kdf, true);
    }

    /// <summary>The fixed octet counts of the values of the algorithms that RFC 9580 and RFC 9980 define with fixed-size strings; null for others.</summary>
    internal static int[]? FixedSizes(PublicKeyAlgorithm algorithm) => algorithm switch
    {
        PublicKeyAlgorithm.X25519 => [32],
        PublicKeyAlgorithm.X448 => [56],
        PublicKeyAlgorithm.Ed25519 => [32],
        PublicKeyAlgorithm.Ed448 => [57],
        PublicKeyAlgorithm.MlDsa65Ed25519 => [32, 1952],
        PublicKeyAlgorithm.MlDsa87Ed448 => [57, 2592],
        PublicKeyAlgorithm.SlhDsaShake128s => [32],
        PublicKeyAlgorithm.SlhDsaShake128f => [32],
        PublicKeyAlgorithm.SlhDsaShake256s => [64],
        PublicKeyAlgorithm.MlKem768X25519 => [32, 1184],
        PublicKeyAlgorithm.MlKem1024X448 => [56, 1568],
        _ => null,
    };

    private static ReadOnlyMemory<byte> ReadOid(ref PacketCursor c)
    {
        // RFC 9580 §5.5.5.2: a one-octet length, and 0 and 0xFF are reserved.
        byte n = c.Byte("curve oid length");
        if (n is 0 or 0xFF)
        {
            throw c.Fail(OpenPgpError.InvalidField, "curve oid length");
        }

        return c.Take(n, "curve oid");
    }
}
