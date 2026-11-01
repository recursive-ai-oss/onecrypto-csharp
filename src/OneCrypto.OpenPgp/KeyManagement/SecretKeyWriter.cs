using System.Buffers.Binary;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Primitives;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>
/// Builds Secret Key and Secret Subkey packets (RFC 9580 §5.5.1.3, §5.5.1.4) from a public key packet and the plain secret values, with or
/// without protection (§5.5.3, §3.7). Version 6 keys are protected with AEAD (usage 253) and Argon2id; version 4 keys with CFB, a SHA-1 check
/// (usage 254) and an iterated and salted S2K.
/// </summary>
internal static class SecretKeyWriter
{
    // RFC 9580 §3.7.1.3: coded count 0xF3 hashes (16 + 3) << (15 + 6) = 39.8 MB per guess, about the cost GnuPG's defaults set.
    internal const byte IteratedCountOctet = 0xF3;

    /// <summary>
    /// Builds a secret key packet.
    /// </summary>
    internal static SecretKeyPacket Build(KeyPacket publicKey, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> password, bool protect, KdfLimits? limits = null)
    {
        limits ??= KdfLimits.Default;
        byte tag = publicKey.IsSubkey ? (byte)PacketTag.SecretSubkey : (byte)PacketTag.SecretKey;
        var body = new List<byte>(publicKey.PublicBody.Length + secret.Length + 96);
        body.AddRange(publicKey.PublicBody.Span);
        if (!protect)
        {
            body.Add(0);
            if (publicKey.Version == 5)
            {
                throw new PgpException(PgpFailure.Unsupported, "Version 5 keys are never written.");
            }

            if (publicKey.Version == 6)
            {
                // RFC 9580 §5.5.3: version 6 carries no checksum when unprotected, and no parameter count either.
                body.AddRange(secret.ToArray());
            }
            else
            {
                body.AddRange(secret.ToArray());
                byte[] sum = new byte[2];
                BinaryPrimitives.WriteUInt16BigEndian(sum, PgpAlgorithms.Checksum(secret));
                body.AddRange(sum);
            }

            return (SecretKeyPacket)Packet.Create(tag, body.ToArray());
        }

        const SymmetricAlgorithm cipher = SymmetricAlgorithm.Aes256;
        int keySize = PgpAlgorithms.KeySize(cipher);
        if (publicKey.Version == 6)
        {
            // RFC 9580 §3.7.1.4, §5.5.3: Argon2id with the second recommended parameter set (t=3, p=4, 64 MiB), OCB, HKDF-derived key.
            const AeadAlgorithm aead = AeadAlgorithm.Ocb;
            byte[] s2kBytes = [(byte)S2kType.Argon2, .. RandomNumberGenerator.GetBytes(16), 3, 4, 16];
            S2kSpecifier s2k = S2kSpecifier.Parse(s2kBytes, out _);
            byte[] kdf = PgpAlgorithms.S2k(s2k, password, keySize, limits);
            byte packetTag = (byte)(0xC0 | tag);
            byte[] kek = HKDF.DeriveKey(HashAlgorithmName.SHA256, kdf, keySize, [], [packetTag, publicKey.Version, (byte)cipher, (byte)aead]);
            CryptographicOperations.ZeroMemory(kdf);
            byte[] ad = [packetTag, .. publicKey.PublicBody.Span];
            byte[] nonce = RandomNumberGenerator.GetBytes(PgpAlgorithms.NonceSize(aead));
            byte[] ct = new byte[secret.Length];
            byte[] tagBytes = new byte[16];
            using (var a = new PgpAlgorithms.Aead(aead, kek))
            {
                a.Encrypt(nonce, secret, ct, tagBytes, ad);
            }

            CryptographicOperations.ZeroMemory(kek);
            byte[] fields = [(byte)cipher, (byte)aead, (byte)s2kBytes.Length, .. s2kBytes, .. nonce];
            body.Add(253);
            body.Add((byte)fields.Length);
            body.AddRange(fields);
            body.AddRange(ct);
            body.AddRange(tagBytes);
        }
        else
        {
            // RFC 9580 §5.5.3: usage 254 is CFB with a SHA-1 hash of the secret values appended before encryption.
            byte[] s2kBytes = [(byte)S2kType.IteratedSalted, (byte)PgpHashAlgorithm.Sha256, .. RandomNumberGenerator.GetBytes(8), IteratedCountOctet];
            S2kSpecifier s2k = S2kSpecifier.Parse(s2kBytes, out _);
            byte[] key = PgpAlgorithms.S2k(s2k, password, keySize, limits);
            byte[] iv = RandomNumberGenerator.GetBytes(16);
            byte[] data = [.. secret, .. PgpAlgorithms.Sha1(secret)];
            byte[] ivWork = (byte[])iv.Clone();
            PgpAlgorithms.CfbEncrypt(key, ivWork, data);
            CryptographicOperations.ZeroMemory(key);
            body.Add(254);
            body.Add((byte)cipher);
            body.AddRange(s2kBytes);
            body.AddRange(iv);
            body.AddRange(data);
        }

        return (SecretKeyPacket)Packet.Create(tag, body.ToArray());
    }

    /// <summary>
    /// Builds a secret key packet from an existing packet's public part and an unlocked key, with a new password or none.
    /// </summary>
    internal static SecretKeyPacket Rebuild(PgpSecretKey unlocked, ReadOnlySpan<byte> newPassword, bool protect, KdfLimits? limits = null) =>
        Build(unlocked.Key.Packet, unlocked.PlainSecret, newPassword, protect, limits);
}
