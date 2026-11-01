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
        byte[] pw = password.ToArray();
        return Build(publicKey, secret, protect, (s2k, size) => PgpAlgorithms.S2k(s2k, pw, size, limits));
    }

    /// <summary>
    /// Builds a secret key packet with the key derivation supplied by the caller: it receives the string-to-key specifier that was written and the key size, and
    /// returns the derived key. The timing test uses it to seal many packets under one derived key without hashing a password each time.
    /// </summary>
    internal static SecretKeyPacket Build(KeyPacket publicKey, ReadOnlySpan<byte> secret, bool protect, Func<S2kSpecifier, int, byte[]> derive)
    {
        // Only version 4 and 6 packets are written: version 5 is LibrePGP's, with its own secret-key layout, and versions 2 and 3 are read-only.
        if (publicKey.Version is not (4 or 6))
        {
            throw new PgpException(PgpFailure.Unsupported, $"Secret keys of version {publicKey.Version} are not written.");
        }

        byte tag = publicKey.IsSubkey ? (byte)PacketTag.SecretSubkey : (byte)PacketTag.SecretKey;
        var body = new List<byte>(publicKey.PublicBody.Length + secret.Length + 96);
        body.AddRange(publicKey.PublicBody.Span);
        if (!protect)
        {
            body.Add(0);
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

        SymmetricAlgorithm cipher = SymmetricAlgorithm.Aes256;
        int keySize = PgpAlgorithms.KeySize(cipher);
        if (publicKey.Version == 6)
        {
            // RFC 9580 §3.7.1.4, §5.5.3: Argon2id with the second recommended parameter set (t=3, p=4, 64 MiB), OCB, HKDF-derived key.
            const AeadAlgorithm aead = AeadAlgorithm.Ocb;
            byte[] s2kBytes = [(byte)S2kType.Argon2, .. RandomNumberGenerator.GetBytes(16), 3, 4, 16];
            S2kSpecifier s2k = S2kSpecifier.Parse(s2kBytes, out _);
            byte[] kdf = derive(s2k, keySize);
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
            PgpHashAlgorithm s2kHash = PgpHashAlgorithm.Sha256;
            if (publicKey.Algorithm == PublicKeyAlgorithm.Ecdh && publicKey.Material.CurveOid.Span.SequenceEqual(SignatureEngine.Curves.Curve25519Legacy))
            {
                // Observed with GnuPG 2.4.8: it cannot use a Curve25519 ECDH subkey whose protection is anything but AES-128 with a SHA-1 S2K (its agent
                // rejects the unprotected scalar as a bad secret key), so keys in that legacy layout carry the protection GnuPG itself writes.
                // The S2K hash only stretches the password here; the iteration count is unchanged.
                cipher = SymmetricAlgorithm.Aes128;
                s2kHash = PgpHashAlgorithm.Sha1;
                keySize = PgpAlgorithms.KeySize(cipher);
            }

            byte[] s2kBytes = [(byte)S2kType.IteratedSalted, (byte)s2kHash, .. RandomNumberGenerator.GetBytes(8), IteratedCountOctet];
            S2kSpecifier s2k = S2kSpecifier.Parse(s2kBytes, out _);
            byte[] key = derive(s2k, keySize);
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
