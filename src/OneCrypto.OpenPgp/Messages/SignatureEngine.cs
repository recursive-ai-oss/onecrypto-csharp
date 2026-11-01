using System.Buffers.Binary;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Primitives;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>Hashing, verification and signature-packet construction (RFC 9580 §5.2).</summary>
internal static class SignatureEngine
{
    /// <summary>RFC 9580 §5.2.3: the salt length that goes with each hash in a v6 signature (half the digest length, at least 16).</summary>
    internal static int SaltLength(PgpHashAlgorithm hash) => hash switch
    {
        PgpHashAlgorithm.Sha256 or PgpHashAlgorithm.Sha3256 or PgpHashAlgorithm.Sha224 => 16,
        PgpHashAlgorithm.Sha384 => 24,
        PgpHashAlgorithm.Sha512 or PgpHashAlgorithm.Sha3512 => 32,
        _ => throw new PgpException(PgpFailure.Unsupported, "Version 6 signatures do not use this hash algorithm."),
    };

    /// <summary>
    /// The hash state for a signature: the v6 salt first (RFC 9580 §5.2.4). The caller then feeds the signed data and calls
    /// <see cref="Finish"/>.
    /// </summary>
    // A modulus the platform refuses (for example one beyond its size limit) makes the key unusable here; that is a typed failure, not a crash.
    internal static void ImportPublicRsa(RSA rsa, byte[] modulus, byte[] exponent)
    {
        try
        {
            rsa.ImportParameters(new RSAParameters { Modulus = modulus, Exponent = exponent });
        }
        catch (CryptographicException e)
        {
            throw new PgpException(PgpFailure.Unsupported, "The platform cannot use this RSA key.", e);
        }
    }

    internal static PgpHash Start(PgpHashAlgorithm hash, ReadOnlySpan<byte> salt)
    {
        var h = new PgpHash(hash);
        if (!salt.IsEmpty)
        {
            h.Append(salt);
        }

        return h;
    }

    /// <summary>The literal-data fields a version 5 document signature covers: format, file name (length-prefixed) and date.</summary>
    internal static byte[] LiteralMeta(byte format, ReadOnlySpan<byte> fileName, uint date)
    {
        byte[] r = new byte[6 + fileName.Length];
        r[0] = format;
        r[1] = (byte)fileName.Length;
        fileName.CopyTo(r.AsSpan(2));
        BinaryPrimitives.WriteUInt32BigEndian(r.AsSpan(2 + fileName.Length), date);
        return r;
    }

    /// <summary>Appends the signed header and the trailer (RFC 9580 §5.2.4) and returns the digest.</summary>
    internal static byte[] Finish(PgpHash h, byte version, ReadOnlySpan<byte> signedHeader, ReadOnlySpan<byte> literalMeta = default)
    {
        h.Append(signedHeader);
        if (version == 5)
        {
            // draft-koch-librepgp §5.2.4: a version 5 document signature also hashes the literal packet's format, file name and date before the trailer.
            // The trailer's eight-octet count covers the signature header only (settled against GnuPG 2.4 and 2.5: counting these fields too does not verify).
            h.Append(literalMeta);
            Span<byte> trailer = new byte[10];
            trailer[0] = version;
            trailer[1] = 0xFF;
            BinaryPrimitives.WriteUInt64BigEndian(trailer[2..], (ulong)signedHeader.Length);
            h.Append(trailer);
        }
        else if (version >= 4)
        {
            // The trailer: version, 0xFF, and the length of everything hashed from the header (four octets, big endian).
            Span<byte> trailer = new byte[6];
            trailer[0] = version;
            trailer[1] = 0xFF;
            BinaryPrimitives.WriteUInt32BigEndian(trailer[2..], (uint)signedHeader.Length);
            h.Append(trailer);
        }

        byte[] digest = h.Finish();
        return digest;
    }

    /// <summary>RFC 9580 §5.2.4: the octets that stand for a key packet when a key signature is hashed.</summary>
    internal static byte[] KeyInput(KeyPacket key)
    {
        ReadOnlySpan<byte> body = key.PublicBody.Span;
        if (key.Version >= 5)
        {
            byte[] b = new byte[5 + body.Length];
            b[0] = key.Version == 5 ? (byte)0x9A : (byte)0x9B;
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(1), (uint)body.Length);
            body.CopyTo(b.AsSpan(5));
            return b;
        }

        byte[] r = new byte[3 + body.Length];
        r[0] = 0x99;
        BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(1), checked((ushort)body.Length));
        body.CopyTo(r.AsSpan(3));
        return r;
    }

    internal static byte[] UserIdInput(Packet userPacket)
    {
        // RFC 9580 §5.2.4: 0xB4 (user ID) or 0xD1 (user attribute) and a four-octet length, then the content.
        byte[] r = new byte[5 + userPacket.Body.Length];
        r[0] = userPacket.Tag == PacketTag.UserAttribute ? (byte)0xD1 : (byte)0xB4;
        BinaryPrimitives.WriteUInt32BigEndian(r.AsSpan(1), (uint)userPacket.Body.Length);
        userPacket.Body.Span.CopyTo(r.AsSpan(5));
        return r;
    }

    /// <summary>Hashes a signature over the given parts and returns the digest.</summary>
    internal static byte[] Digest(SignaturePacket sig, params ReadOnlyMemory<byte>[] parts)
    {
        using PgpHash h = Start(sig.Hash, sig.Salt.Span);
        foreach (ReadOnlyMemory<byte> p in parts)
        {
            h.Append(p.Span);
        }

        return Finish(h, sig.Version, sig.SignedHeader.Span);
    }

    /// <summary>
    /// Checks the signature value in <paramref name="sig"/> over <paramref name="digest"/> with the public key. Returns false for a bad signature;
    /// throws <see cref="PgpException"/> with <see cref="PgpFailure.Unsupported"/> for an algorithm that is not available.
    /// </summary>
    internal static bool VerifyDigest(KeyPacket key, SignaturePacket sig, ReadOnlySpan<byte> digest)
    {
        // RFC 9580 §5.2.3: the two octets after the hashed area are the leftmost 16 bits of the digest; a mismatch is a bad signature without any public-key work.
        if (sig.HashPrefix.Length != 2 || digest.Length < 2 || !digest[..2].SequenceEqual(sig.HashPrefix.Span))
        {
            return false;
        }

        PublicKeyMaterial pub = key.Material;
        IReadOnlyList<ReadOnlyMemory<byte>> sv = sig.Material.Values;
        if (!sig.Material.IsKnown)
        {
            throw new PgpException(PgpFailure.Unsupported, $"The signature algorithm {(byte)sig.Algorithm} is not supported.");
        }

        switch (sig.Algorithm)
        {
            case PublicKeyAlgorithm.Rsa:
            case PublicKeyAlgorithm.RsaSignOnly:
                {
                    byte[] n = pub.Values[0].ToArray();
                    byte[] s = LeftPad(sv[0].Span, n.Length);
                    if (PgpHash.IsManaged(sig.Hash))
                    {
                        // The platform cannot name these hashes in a PKCS#1 verification; our verify-only RSA takes the finished digest.
                        return RecursiveAI.OneCrypto.Primitives.Fallback.RsaVerifier.VerifyPkcs1(n, pub.Values[1].Span, PgpAlgorithms.HashName(sig.Hash), digest, s);
                    }

                    using var rsa = RSA.Create();
                    ImportPublicRsa(rsa, n, pub.Values[1].ToArray());
                    return rsa.VerifyHash(digest, s, PgpAlgorithms.HashName(sig.Hash), RSASignaturePadding.Pkcs1);
                }

            case PublicKeyAlgorithm.Ecdsa:
                {
                    ECCurve curve = Curves.Find(pub.CurveOid.Span, out int size);
                    ReadOnlySpan<byte> q = pub.Values[0].Span;
                    if (q.Length != 1 + 2 * size || q[0] != 4)
                    {
                        return false;
                    }

                    using var ec = ECDsa.Create(new ECParameters { Curve = curve, Q = new ECPoint { X = q.Slice(1, size).ToArray(), Y = q.Slice(1 + size, size).ToArray() } });
                    if (sv[0].Length > size || sv[1].Length > size)
                    {
                        return false;
                    }

                    byte[] rs = new byte[2 * size];
                    sv[0].Span.CopyTo(rs.AsSpan(size - sv[0].Length));
                    sv[1].Span.CopyTo(rs.AsSpan(2 * size - sv[1].Length));
                    return ec.VerifyHash(digest, rs, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                }

            case PublicKeyAlgorithm.EdDsaLegacy:
                {
                    ReadOnlySpan<byte> q = pub.Values[0].Span;
                    if (q.Length != 33 || q[0] != 0x40 || sv[0].Length > 32 || sv[1].Length > 32)
                    {
                        return false;
                    }

                    byte[] rs = new byte[64];
                    sv[0].Span.CopyTo(rs.AsSpan(32 - sv[0].Length));
                    sv[1].Span.CopyTo(rs.AsSpan(64 - sv[1].Length));
                    return Ed25519.Verify(q[1..], digest, rs);
                }

            case PublicKeyAlgorithm.Ed25519:
                return Ed25519.Verify(pub.Values[0].Span, digest, sv[0].Span);
            case PublicKeyAlgorithm.Ed448:
                return Ed448.Verify(pub.Values[0].Span, digest, default, sv[0].Span);
            case PublicKeyAlgorithm.MlDsa65Ed25519:
            case PublicKeyAlgorithm.MlDsa87Ed448:
                {
                    // RFC 9980 §5.2.3, §5.3.1: both signatures must verify; version 6 only, digest of at least 256 bits.
                    if (sig.Version != 6 || PgpAlgorithms.HashSize(sig.Hash) < 32)
                    {
                        return false;
                    }

                    bool is25519 = sig.Algorithm == PublicKeyAlgorithm.MlDsa65Ed25519;
                    bool edOk = is25519 ? Ed25519.Verify(pub.Values[0].Span, digest, sv[0].Span) : Ed448.Verify(pub.Values[0].Span, digest, default, sv[0].Span);
                    RecursiveAI.OneCrypto.Internal.Platform.RequireMlDsa();
                    using MLDsa ml = MLDsa.ImportMLDsaPublicKey(is25519 ? MLDsaAlgorithm.MLDsa65 : MLDsaAlgorithm.MLDsa87, pub.Values[1].Span);
                    bool mlOk = ml.VerifyData(digest, sv[1].Span);
                    return edOk & mlOk;
                }

            case PublicKeyAlgorithm.Dsa:
                {
                    using var dsa = DSA.Create();
                    dsa.ImportParameters(new DSAParameters
                    {
                        P = pub.Values[0].ToArray(),
                        Q = pub.Values[1].ToArray(),
                        G = pub.Values[2].ToArray(),
                        Y = pub.Values[3].ToArray(),
                    });
                    int qLen = pub.Values[1].Length;
                    if (sv[0].Length > qLen || sv[1].Length > qLen)
                    {
                        return false;
                    }

                    byte[] rs = new byte[2 * qLen];
                    sv[0].Span.CopyTo(rs.AsSpan(qLen - sv[0].Length));
                    sv[1].Span.CopyTo(rs.AsSpan(2 * qLen - sv[1].Length));
                    return dsa.VerifySignature(digest.Length > qLen ? digest[..qLen] : digest, rs, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                }

            default:
                throw new PgpException(PgpFailure.Unsupported, $"The signature algorithm {(byte)sig.Algorithm} ({sig.Algorithm}) is not supported.");
        }
    }

    internal static byte[] LeftPad(ReadOnlySpan<byte> value, int length)
    {
        if (value.Length > length)
        {
            // A signature integer longer than the modulus cannot be valid; hand the verifier something it rejects.
            return new byte[length];
        }

        byte[] r = new byte[length];
        value.CopyTo(r.AsSpan(length - value.Length));
        return r;
    }

    internal static byte[] Mpi(ReadOnlySpan<byte> value)
    {
        while (value.Length > 0 && value[0] == 0)
        {
            value = value[1..];
        }

        int bits = value.Length == 0 ? 0 : (value.Length - 1) * 8 + (8 - System.Numerics.BitOperations.LeadingZeroCount((uint)value[0]) + 24);
        byte[] r = new byte[2 + value.Length];
        BinaryPrimitives.WriteUInt16BigEndian(r, (ushort)bits);
        value.CopyTo(r.AsSpan(2));
        return r;
    }

    /// <summary>The named curves of RFC 9580 §9.2 that the platform provides, by OID octets.</summary>
    internal static class Curves
    {
        private static readonly (byte[] Oid, string Dotted, int Size)[] Table =
        [
            ([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07], "1.2.840.10045.3.1.7", 32),
            ([0x2B, 0x81, 0x04, 0x00, 0x22], "1.3.132.0.34", 48),
            ([0x2B, 0x81, 0x04, 0x00, 0x23], "1.3.132.0.35", 66),
            ([0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07], "1.3.36.3.3.2.8.1.1.7", 32),
            ([0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B], "1.3.36.3.3.2.8.1.1.11", 48),
            ([0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D], "1.3.36.3.3.2.8.1.1.13", 64),
        ];

        internal static ECCurve Find(ReadOnlySpan<byte> oid, out int size)
        {
            foreach ((byte[] o, string dotted, int s) in Table)
            {
                if (oid.SequenceEqual(o))
                {
                    size = s;
                    return ECCurve.CreateFromValue(dotted);
                }
            }

            throw new PgpException(PgpFailure.Unsupported, "The elliptic curve is not supported.");
        }

        internal static bool TryFind(ReadOnlySpan<byte> oid, out int size)
        {
            foreach ((byte[] o, _, int s) in Table)
            {
                if (oid.SequenceEqual(o))
                {
                    size = s;
                    return true;
                }
            }

            size = 0;
            return false;
        }

        internal static readonly byte[] X25519Oid = [0x2B, 0x65, 0x6E];

        /// <summary>
        /// Curve25519 for ECDH under either name: the legacy OID of RFC 9580 §9.2 and 1.3.101.110, which GnuPG 2.5 puts in the ECDH keys it makes. Both carry the
        /// point as 0x40 and 32 octets and the scalar as a big-endian MPI.
        /// </summary>
        internal static bool IsCurve25519(ReadOnlySpan<byte> oid) => oid.SequenceEqual(Curve25519Legacy) || oid.SequenceEqual(X25519Oid);

        internal static readonly byte[] Curve25519Legacy = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];
        internal static readonly byte[] Ed25519Legacy = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
    }
}
