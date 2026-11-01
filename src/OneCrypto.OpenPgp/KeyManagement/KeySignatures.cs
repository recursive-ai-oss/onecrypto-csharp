using System.Buffers.Binary;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Policy;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>A signature whose digest is computed and whose header is fixed, waiting for the public-key operation (RFC 9580 §5.2.4).</summary>
internal sealed class PendingSignature
{
    internal PendingSignature(KeyPacket key, byte version, SignatureType type, PgpHashAlgorithm hash, byte[] signedHeader, byte[] unhashedRaw, byte[] salt, byte[] digest)
    {
        Key = key;
        Version = version;
        Type = type;
        Hash = hash;
        SignedHeader = signedHeader;
        UnhashedRaw = unhashedRaw;
        Salt = salt;
        Digest = digest;
    }

    internal KeyPacket Key { get; }

    internal byte Version { get; }

    internal SignatureType Type { get; }

    internal PgpHashAlgorithm Hash { get; }

    internal byte[] SignedHeader { get; }

    internal byte[] UnhashedRaw { get; }

    internal byte[] Salt { get; }

    internal byte[] Digest { get; }

    /// <summary>Assembles the signature packet around the algorithm-specific fields (RFC 9580 §5.2.3).</summary>
    internal SignaturePacket Assemble(ReadOnlySpan<byte> material)
    {
        var body = new List<byte>(SignedHeader);
        if (Version == 6)
        {
            body.AddRange(BigEndian((uint)UnhashedRaw.Length));
        }
        else
        {
            byte[] l = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(l, (ushort)UnhashedRaw.Length);
            body.AddRange(l);
        }

        body.AddRange(UnhashedRaw);
        body.Add(Digest[0]);
        body.Add(Digest[1]);
        if (Version == 6)
        {
            body.Add((byte)Salt.Length);
            body.AddRange(Salt);
        }

        body.AddRange(material.ToArray());
        return (SignaturePacket)Packet.Create((byte)PacketTag.Signature, body.ToArray());
    }

    private static byte[] BigEndian(uint v)
    {
        byte[] b = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, v);
        return b;
    }
}

/// <summary>
/// Makes the signatures key management needs: self-signatures, bindings, certifications, revocations (RFC 9580 §5.2.1, §10.1). Every signature carries
/// its creation time and the issuer fingerprint first, then the caller's subpackets.
/// </summary>
internal static class KeySignatures
{
    /// <summary>
    /// Fixes the header and computes the digest over the given hashed parts (key packets, User IDs: RFC 9580 §5.2.4), without signing.
    /// </summary>
    internal static PendingSignature Begin(KeyPacket signerKey, SignatureType type, IEnumerable<SignatureSubpacket> hashed, IEnumerable<SignatureSubpacket> unhashed,
        DateTimeOffset now, CryptoPolicy policy, PgpHashAlgorithm? hash, Action<SigHasher>? feed)
    {
        if (signerKey.Version is not (4 or 6))
        {
            throw new PgpException(PgpFailure.Unsupported, "Only version 4 and version 6 keys sign.");
        }

        PgpHashAlgorithm h = hash ?? SignatureBuilder.DefaultHash(signerKey);
        PolicyDecision d = policy.CheckHash(PgpAlgorithms.HashName(h), CryptoUse.Sign, now);
        if (d.Verdict == PolicyVerdict.Rejected)
        {
            throw new PgpException(PgpFailure.PolicyViolation, d.Reason);
        }

        if (signerKey.Algorithm is PublicKeyAlgorithm.Rsa or PublicKeyAlgorithm.RsaSignOnly && signerKey.Material.IsKnown
            && PgpAlgorithms.BitLength(signerKey.Material.Values[0].Span) < policy.MinRsaBitsNew)
        {
            throw new PgpException(PgpFailure.PolicyViolation, "The RSA key is smaller than the policy allows for new signatures.");
        }

        byte version = signerKey.Version == 6 ? (byte)6 : (byte)4;
        byte[] salt = version == 6 ? RandomNumberGenerator.GetBytes(SignatureEngine.SaltLength(h)) : [];
        var hashedList = new List<SignatureSubpacket>
        {
            Subpackets.CreationTime(now),
            Subpackets.IssuerFingerprint(signerKey),
        };
        hashedList.AddRange(hashed);
        var unhashedList = new List<SignatureSubpacket>();
        if (version == 4)
        {
            unhashedList.Add(SignatureSubpacket.Create((byte)SubpacketType.IssuerKeyId, false, signerKey.GetKeyId()));
        }

        unhashedList.AddRange(unhashed);
        byte[] hashedRaw = SubpacketArea.Create(hashedList).Raw.ToArray();
        byte[] unhashedRaw = SubpacketArea.Create(unhashedList).Raw.ToArray();
        var head = new List<byte> { version, (byte)type, (byte)signerKey.Algorithm, (byte)h };
        if (version == 6)
        {
            byte[] l = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(l, (uint)hashedRaw.Length);
            head.AddRange(l);
        }
        else
        {
            byte[] l = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(l, (ushort)hashedRaw.Length);
            head.AddRange(l);
        }

        head.AddRange(hashedRaw);
        byte[] signedHeader = head.ToArray();
        using var hasher = new SigHasher(h, salt, type == SignatureType.Text);
        feed?.Invoke(hasher);
        byte[] digest = hasher.Finish(version, signedHeader);
        return new PendingSignature(signerKey, version, type, h, signedHeader, unhashedRaw, salt, digest);
    }

    /// <summary>Begins and finishes a signature over key material parts, signing with an unlocked key.</summary>
    internal static SignaturePacket Make(PgpSecretKey signer, SignatureType type, IEnumerable<SignatureSubpacket> hashed, DateTimeOffset now, CryptoPolicy policy,
        params ReadOnlyMemory<byte>[] parts) =>
        MakeWith(signer, type, hashed, [], now, policy, parts);

    internal static SignaturePacket MakeWith(PgpSecretKey signer, SignatureType type, IEnumerable<SignatureSubpacket> hashed, IEnumerable<SignatureSubpacket> unhashed,
        DateTimeOffset now, CryptoPolicy policy, params ReadOnlyMemory<byte>[] parts)
    {
        PendingSignature p = Begin(signer.Key.Packet, type, hashed, unhashed, now, policy, null, h =>
        {
            foreach (ReadOnlyMemory<byte> part in parts)
            {
                h.Append(part.Span);
            }
        });
        byte[] material = SignatureMaterialBuilder.Sign(signer, p.Hash, p.Version, p.Digest);
        return p.Assemble(material);
    }
}

/// <summary>Constructors for the signature subpackets key management writes (RFC 9580 §5.2.3).</summary>
internal static class Subpackets
{
    internal static SignatureSubpacket CreationTime(DateTimeOffset t) => SignatureSubpacket.Create((byte)SubpacketType.SignatureCreationTime, false, PgpTime.FourOctets(t));

    internal static SignatureSubpacket IssuerFingerprint(KeyPacket k) =>
        SignatureSubpacket.Create((byte)SubpacketType.IssuerFingerprint, false, new byte[] { k.Version }.Concat(k.GetFingerprint()).ToArray());

    internal static SignatureSubpacket KeyFlags(PgpKeyUsage usage) =>
        SignatureSubpacket.Create((byte)SubpacketType.KeyFlags, false, new[] { (byte)usage });

    /// <summary>Seconds after key creation (RFC 9580 §5.2.3.13); zero means the key does not expire.</summary>
    internal static SignatureSubpacket KeyExpiration(uint seconds)
    {
        byte[] b = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, seconds);
        return SignatureSubpacket.Create((byte)SubpacketType.KeyExpirationTime, false, b);
    }

    internal static SignatureSubpacket Features(byte features) => SignatureSubpacket.Create((byte)SubpacketType.Features, false, new[] { features });

    internal static SignatureSubpacket PrimaryUserId(bool primary) => SignatureSubpacket.Create((byte)SubpacketType.PrimaryUserId, false, new[] { primary ? (byte)1 : (byte)0 });

    internal static SignatureSubpacket Revocation(byte code, string text) =>
        SignatureSubpacket.Create((byte)SubpacketType.ReasonForRevocation, false, new byte[] { code }.Concat(System.Text.Encoding.UTF8.GetBytes(text)).ToArray());

    internal static SignatureSubpacket EmbeddedSignature(SignaturePacket s) => SignatureSubpacket.Create((byte)SubpacketType.EmbeddedSignature, false, s.Body);
}
