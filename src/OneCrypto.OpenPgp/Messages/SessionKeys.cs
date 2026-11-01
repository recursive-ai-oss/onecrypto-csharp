using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Primitives;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>Public-key encryption of session keys and the matching decryption (RFC 9580 §5.1, §11.5).</summary>
internal static class SessionKeys
{
    private static readonly byte[] AnonymousSender = Encoding.ASCII.GetBytes("Anonymous Sender    ");

    /// <summary>The result of unwrapping a PKESK: the session key and, for a v3 packet, the symmetric algorithm that travelled with it.</summary>
    internal readonly record struct Recovered(SymmetricAlgorithm? Cipher, byte[] Key);

    // ---- decrypt ----

    /// <summary>
    /// Recovers the session key from a PKESK with an unlocked key. Every failure (wrong key, bad padding, bad checksum, bad unwrap) returns null,
    /// so the caller can say only "cannot decrypt" (RFC 9580 §13).
    /// </summary>
    internal static Recovered? Decrypt(PgpSecretKey key, PublicKeyEncryptedSessionKeyPacket p)
    {
        try
        {
            if (key.Key.Algorithm != p.Algorithm && !(p.Algorithm is PublicKeyAlgorithm.Rsa or PublicKeyAlgorithm.RsaEncryptOnly && key.Key.Algorithm is PublicKeyAlgorithm.Rsa or PublicKeyAlgorithm.RsaEncryptOnly))
            {
                return null;
            }

            switch (p.Algorithm)
            {
                case PublicKeyAlgorithm.Rsa:
                case PublicKeyAlgorithm.RsaEncryptOnly:
                    return DecryptRsa(key, p);
                case PublicKeyAlgorithm.X25519:
                    return DecryptNative(key, p, 32, "OpenPGP X25519", HashAlgorithmName.SHA256, 16);
                case PublicKeyAlgorithm.X448:
                    return DecryptNative(key, p, 56, "OpenPGP X448", HashAlgorithmName.SHA512, 32);
                case PublicKeyAlgorithm.Ecdh:
                    return DecryptEcdh(key, p);
                case PublicKeyAlgorithm.MlKem768X25519:
                case PublicKeyAlgorithm.MlKem1024X448:
                    return PqcSessionKeys.Decrypt(key, p);
                case PublicKeyAlgorithm.LibrePgpKyber:
                    return LibrePgpKyber.Decrypt(key, p);
                default:
                    return null;
            }
        }
        catch (CryptographicException)
        {
            return null;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static Recovered? DecryptRsa(PgpSecretKey key, PublicKeyEncryptedSessionKeyPacket p)
    {
        var rsa = (IDecryptionKey)key.SigningKey;
        int n = key.Key.Packet.Material.Values[0].Length;
        byte[] c = SignatureEngine.LeftPad(p.Values[0].Span, n);
        byte[] m = rsa.Decrypt(c, DecryptionSpec.RsaPkcs1());
        try
        {
            return FromChecksummed(m, p.Version == 3, padded: false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(m);
        }
    }

    private static Recovered? DecryptNative(PgpSecretKey key, PublicKeyEncryptedSessionKeyPacket p, int size, string info, HashAlgorithmName hash, int kekSize)
    {
        List<byte[]> sec = key.SecretParts();
        byte[] eph = p.Values[0].ToArray();
        byte[] pub = key.Key.Packet.Material.Values[0].ToArray();
        byte[] shared = new byte[size];
        bool ok = size == 32 ? X25519.TryDeriveSharedSecret(sec[0], eph, shared) : X448.TryDeriveSharedSecret(sec[0], eph, shared);
        if (!ok)
        {
            return null;
        }

        byte[] ikm = [.. eph, .. pub, .. shared];
        byte[] kek = HKDF.DeriveKey(hash, ikm, kekSize, [], Encoding.ASCII.GetBytes(info));
        CryptographicOperations.ZeroMemory(shared);
        CryptographicOperations.ZeroMemory(ikm);
        ReadOnlySpan<byte> wrapped = p.Values[1].Span;
        SymmetricAlgorithm? cipher = null;
        if (p.Version == 3)
        {
            // RFC 9580 §5.1.6: in a v3 packet the symmetric algorithm precedes the wrapped key, in the clear.
            if (wrapped.Length < 1)
            {
                return null;
            }

            cipher = (SymmetricAlgorithm)wrapped[0];
            wrapped = wrapped[1..];
        }

        if (wrapped.Length < 24 || wrapped.Length > 8 + 64)
        {
            return null;
        }

        byte[] sk = new byte[wrapped.Length - 8];
        using var kw = new AesKeyWrap(kek);
        CryptographicOperations.ZeroMemory(kek);
        if (!kw.TryUnwrap(wrapped, sk))
        {
            return null;
        }

        return new Recovered(cipher, sk);
    }

    private static Recovered? DecryptEcdh(PgpSecretKey key, PublicKeyEncryptedSessionKeyPacket p)
    {
        PublicKeyMaterial pubm = key.Key.Packet.Material;
        ReadOnlySpan<byte> kdfp = pubm.KdfParameters.Span;
        byte hashId = kdfp[1];
        byte symId = kdfp[2];
        byte[] zb;
        ReadOnlySpan<byte> eph = p.Values[0].Span;
        List<byte[]> sec = key.SecretParts();
        if (SignatureEngine.Curves.IsCurve25519(pubm.CurveOid.Span))
        {
            if (eph.Length != 33 || eph[0] != 0x40)
            {
                return null;
            }

            byte[] scalar = SignatureEngine.LeftPad(sec[0], 32);
            Array.Reverse(scalar);
            zb = new byte[32];
            bool ok = X25519.TryDeriveSharedSecret(scalar, eph[1..], zb);
            CryptographicOperations.ZeroMemory(scalar);
            if (!ok)
            {
                return null;
            }
        }
        else
        {
            ECCurve curve = SignatureEngine.Curves.Find(pubm.CurveOid.Span, out int size);
            if (eph.Length != 1 + 2 * size || eph[0] != 4)
            {
                return null;
            }

            ReadOnlySpan<byte> q = pubm.Values[0].Span;
            using var mine = ECDiffieHellman.Create(new ECParameters
            {
                Curve = curve,
                D = SignatureEngine.LeftPad(sec[0], size),
                Q = new ECPoint { X = q.Slice(1, size).ToArray(), Y = q.Slice(1 + size, size).ToArray() },
            });
            using var theirs = ECDiffieHellman.Create(new ECParameters { Curve = curve, Q = new ECPoint { X = eph.Slice(1, size).ToArray(), Y = eph.Slice(1 + size, size).ToArray() } });
            zb = mine.DeriveRawSecretAgreement(theirs.PublicKey);
        }

        byte[] kek = EcdhKdf(pubm.CurveOid.Span, kdfp, key.Key.Packet, zb, (PgpHashAlgorithm)hashId, (SymmetricAlgorithm)symId);
        CryptographicOperations.ZeroMemory(zb);
        ReadOnlySpan<byte> wrapped = p.Values[1].Span;
        if (wrapped.Length < 16 || wrapped.Length % 8 != 0)
        {
            return null;
        }

        byte[] m = new byte[wrapped.Length - 8];
        using var kw = new AesKeyWrap(kek);
        CryptographicOperations.ZeroMemory(kek);
        if (!kw.TryUnwrap(wrapped, m))
        {
            return null;
        }

        try
        {
            return FromChecksummed(m, p.Version == 3, padded: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(m);
        }
    }

    /// <summary>RFC 9580 §11.4 and §11.5: the single-round concatenation KDF over the shared point and the recipient-binding parameters.</summary>
    private static byte[] EcdhKdf(ReadOnlySpan<byte> oid, ReadOnlySpan<byte> kdfParameters, KeyPacket recipient, ReadOnlySpan<byte> zb, PgpHashAlgorithm hash, SymmetricAlgorithm wrap)
    {
        // draft-koch-librepgp §13.5: the KDF names a 20-octet fingerprint, the leftmost 20 octets of a version 5 key's 32.
        byte[] fp = recipient.GetFingerprint();
        if (fp.Length > 20)
        {
            fp = fp[..20];
        }

        var param = new List<byte> { (byte)oid.Length };
        param.AddRange(oid.ToArray());
        param.Add((byte)PublicKeyAlgorithm.Ecdh);
        param.Add((byte)kdfParameters.Length);
        param.AddRange(kdfParameters.ToArray());
        param.AddRange(AnonymousSender);
        param.AddRange(fp);
        byte[] input = [0, 0, 0, 1, .. zb, .. param];
        byte[] digest = CryptographicOperations.HashData(PgpAlgorithms.HashName(hash), input);
        int kek = PgpAlgorithms.KeySize(wrap);
        if (digest.Length < kek)
        {
            throw new PgpException(PgpFailure.Unsupported, "The ECDH key-wrap hash is too short for the wrapping cipher.");
        }

        byte[] r = digest.AsSpan(0, kek).ToArray();
        CryptographicOperations.ZeroMemory(digest);
        return r;
    }

    /// <summary>
    /// Strips the optional algorithm octet and PKCS#5 padding and checks the two-octet sum (RFC 9580 §5.1.3, §11.5). Validity is
    /// accumulated in a mask and tested once at the end, so no branch or loop bound depends on the unwrapped bytes or on whether the
    /// padding or the checksum matched (RFC 9580 §13: a caller must not learn which check failed). Only the message lengths, which are public,
    /// and the padding count, which is validated in the same mask, steer control flow.
    /// </summary>
    internal static Recovered? FromChecksummed(ReadOnlySpan<byte> m, bool v3, bool padded)
    {
        int len = m.Length;
        uint bad = 0;
        uint pad = 0;
        if (padded)
        {
            if (len < 8)
            {
                return null;
            }

            // RFC 9580 §11.5: the padding is PKCS #5 style (each octet holds the count), and a sender may pad the value to 40 octets to hide the key size,
            // which is up to 22 octets of padding. 24 leaves a little room; the loop bound depends on the public length only.
            const uint MaxPad = 24;
            pad = m[^1];
            bad |= IsZero(pad);
            uint over = (MaxPad - pad) >> 31; // 1 when pad > MaxPad
            bad |= over;
            pad ^= (pad ^ 8) & (0 - over); // keep the arithmetic below inside 1..MaxPad whatever the input
            int span = Math.Min(len, (int)MaxPad);
            for (int i = 0; i < span; i++)
            {
                uint inPad = ((uint)(i - (int)pad) >> 31) & 1; // 1 when i < pad
                bad |= (0 - inPad) & (uint)(m[len - 1 - i] ^ (byte)pad);
            }
        }

        int head = v3 ? 1 : 0;
        int keyLen = len - (int)pad - head - 2;
        bad |= (uint)keyLen >> 31; // too short for a key and a checksum
        keyLen &= ~(keyLen >> 31);
        // One pass over every octet after the algorithm octet, so the work is the same whatever the padding and checksum turned out to be:
        // sum the key octets and pick up the two checksum octets by position, all with masks.
        uint sum = 0;
        uint stored = 0;
        for (int j = head; j < len; j++)
        {
            uint b = m[j];
            int rel = j - head;
            uint inKey = (uint)(rel - keyLen) >> 31; // 1 when rel < keyLen
            sum += b & (0 - inKey);
            stored |= (b << 8) & (0 - IsZero((uint)(rel ^ keyLen)));
            stored |= b & (0 - IsZero((uint)(rel ^ (keyLen + 1))));
        }

        bad |= (sum ^ stored) & 0xFFFF;
        bad |= IsZero((uint)keyLen);
        if (bad != 0)
        {
            return null;
        }

        return new Recovered(v3 ? (SymmetricAlgorithm)m[0] : null, m.Slice(head, keyLen).ToArray());
    }

    /// <summary>1 when the value is zero, else 0, without a branch.</summary>
    private static uint IsZero(uint v) => ((v | (0 - v)) >> 31) ^ 1;

    // ---- encrypt ----

    /// <summary>Builds a PKESK packet that carries <paramref name="sessionKey"/> to <paramref name="recipient"/>.</summary>
    internal static Packet Encrypt(PgpKey recipient, byte[] sessionKey, SymmetricAlgorithm cipher, int pkeskVersion)
    {
        KeyPacket kp = recipient.Packet;
        PublicKeyMaterial pm = kp.Material;
        var body = new List<byte> { (byte)pkeskVersion };
        if (pkeskVersion == 3)
        {
            body.AddRange(kp.GetKeyId());
        }
        else
        {
            byte[] fp = kp.GetFingerprint();
            body.Add((byte)(1 + fp.Length));
            body.Add(kp.Version);
            body.AddRange(fp);
        }

        body.Add((byte)kp.Algorithm);
        bool v3 = pkeskVersion == 3;
        switch (kp.Algorithm)
        {
            case PublicKeyAlgorithm.Rsa:
            case PublicKeyAlgorithm.RsaEncryptOnly:
                {
                    byte[] m = Checksummed(sessionKey, v3 ? cipher : null, pad: false);
                    using var rsa = RSA.Create();
                    SignatureEngine.ImportPublicRsa(rsa, pm.Values[0].ToArray(), pm.Values[1].ToArray());
                    byte[] c = rsa.Encrypt(m, RSAEncryptionPadding.Pkcs1);
                    CryptographicOperations.ZeroMemory(m);
                    body.AddRange(SignatureEngine.Mpi(c));
                    break;
                }

            case PublicKeyAlgorithm.X25519:
            case PublicKeyAlgorithm.X448:
                {
                    bool is25519 = kp.Algorithm == PublicKeyAlgorithm.X25519;
                    int size = is25519 ? 32 : 56;
                    byte[] eSec = RandomNumberGenerator.GetBytes(size);
                    byte[] ePub = new byte[size];
                    byte[] shared = new byte[size];
                    byte[] recipientPub = pm.Values[0].ToArray();
                    bool ok;
                    if (is25519)
                    {
                        X25519.DerivePublicKey(eSec, ePub);
                        ok = X25519.TryDeriveSharedSecret(eSec, recipientPub, shared);
                    }
                    else
                    {
                        X448.DerivePublicKey(eSec, ePub);
                        ok = X448.TryDeriveSharedSecret(eSec, recipientPub, shared);
                    }

                    CryptographicOperations.ZeroMemory(eSec);
                    if (!ok)
                    {
                        throw new PgpException(PgpFailure.KeyCannotPerform, "The recipient's key is a low-order point.");
                    }

                    byte[] ikm = [.. ePub, .. recipientPub, .. shared];
                    byte[] kek = is25519
                        ? HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 16, [], Encoding.ASCII.GetBytes("OpenPGP X25519"))
                        : HKDF.DeriveKey(HashAlgorithmName.SHA512, ikm, 32, [], Encoding.ASCII.GetBytes("OpenPGP X448"));
                    CryptographicOperations.ZeroMemory(ikm);
                    CryptographicOperations.ZeroMemory(shared);
                    byte[] wrapped = new byte[sessionKey.Length + 8];
                    using (var kw = new AesKeyWrap(kek))
                    {
                        kw.Wrap(sessionKey, wrapped);
                    }

                    CryptographicOperations.ZeroMemory(kek);
                    body.AddRange(ePub);
                    body.Add((byte)(wrapped.Length + (v3 ? 1 : 0)));
                    if (v3)
                    {
                        body.Add((byte)cipher);
                    }

                    body.AddRange(wrapped);
                    break;
                }

            case PublicKeyAlgorithm.MlKem768X25519:
            case PublicKeyAlgorithm.MlKem1024X448:
                body.AddRange(PqcSessionKeys.Encrypt(kp.Algorithm, pm, sessionKey, cipher, v3));
                break;
            case PublicKeyAlgorithm.Ecdh:
                body.AddRange(EncryptEcdh(recipient, sessionKey, v3 ? cipher : null));
                break;
            case PublicKeyAlgorithm.LibrePgpKyber when v3:
                body.AddRange(LibrePgpKyber.Encrypt(recipient, sessionKey, cipher));
                break;
            default:
                throw new PgpException(PgpFailure.Unsupported, $"Encrypting to the key algorithm {(byte)kp.Algorithm} ({kp.Algorithm}) is not supported.");
        }

        return Packet.Create((byte)PacketTag.PublicKeyEncryptedSessionKey, body.ToArray());
    }

    private static byte[] Checksummed(byte[] sessionKey, SymmetricAlgorithm? cipher, bool pad)
    {
        int head = cipher is null ? 0 : 1;
        int len = head + sessionKey.Length + 2;
        int padding = pad ? 8 - (len % 8) : 0;
        byte[] m = new byte[len + padding];
        if (cipher is { } c)
        {
            m[0] = (byte)c;
        }

        sessionKey.CopyTo(m, head);
        BinaryPrimitives.WriteUInt16BigEndian(m.AsSpan(head + sessionKey.Length), PgpAlgorithms.Checksum(sessionKey));
        for (int i = 0; i < padding; i++)
        {
            m[len + i] = (byte)padding;
        }

        return m;
    }

    private static byte[] EncryptEcdh(PgpKey recipient, byte[] sessionKey, SymmetricAlgorithm? v3Cipher)
    {
        PublicKeyMaterial pm = recipient.Packet.Material;
        ReadOnlySpan<byte> kdfp = pm.KdfParameters.Span;
        var hash = (PgpHashAlgorithm)kdfp[1];
        var wrap = (SymmetricAlgorithm)kdfp[2];
        // RFC 9580 §11.5 (RFC 6637 §13): the key is wrapped with AES key wrap under a KDF hash of at least SHA2-256. A key that
        // names anything else is not one we encrypt to, rather than a message the recipient cannot be expected to open.
        if (wrap is not (SymmetricAlgorithm.Aes128 or SymmetricAlgorithm.Aes192 or SymmetricAlgorithm.Aes256)
            || hash is not (PgpHashAlgorithm.Sha256 or PgpHashAlgorithm.Sha384 or PgpHashAlgorithm.Sha512))
        {
            throw new PgpException(PgpFailure.KeyCannotPerform, "The recipient's ECDH key names key-wrap parameters that are not acceptable for encryption.");
        }

        byte[] zb;
        byte[] ephPoint;
        if (SignatureEngine.Curves.IsCurve25519(pm.CurveOid.Span))
        {
            byte[] eSec = RandomNumberGenerator.GetBytes(32);
            byte[] ePub = new byte[32];
            X25519.DerivePublicKey(eSec, ePub);
            ReadOnlySpan<byte> q = pm.Values[0].Span;
            zb = new byte[32];
            if (q.Length != 33 || !X25519.TryDeriveSharedSecret(eSec, q[1..], zb))
            {
                throw new PgpException(PgpFailure.KeyCannotPerform, "The recipient's ECDH key is not usable.");
            }

            CryptographicOperations.ZeroMemory(eSec);
            ephPoint = [0x40, .. ePub];
        }
        else
        {
            ECCurve curve = SignatureEngine.Curves.Find(pm.CurveOid.Span, out int size);
            ReadOnlySpan<byte> q = pm.Values[0].Span;
            using var eph = ECDiffieHellman.Create(curve);
            using var theirs = ECDiffieHellman.Create(new ECParameters { Curve = curve, Q = new ECPoint { X = q.Slice(1, size).ToArray(), Y = q.Slice(1 + size, size).ToArray() } });
            zb = eph.DeriveRawSecretAgreement(theirs.PublicKey);
            ECParameters ep = eph.ExportParameters(false);
            ephPoint = [4, .. SignatureEngine.LeftPad(ep.Q.X, size), .. SignatureEngine.LeftPad(ep.Q.Y, size)];
        }

        byte[] kek = EcdhKdf(pm.CurveOid.Span, kdfp, recipient.Packet, zb, hash, wrap);
        CryptographicOperations.ZeroMemory(zb);
        byte[] m = Checksummed(sessionKey, v3Cipher, pad: true);
        byte[] wrapped = new byte[m.Length + 8];
        using (var kw = new AesKeyWrap(kek))
        {
            kw.Wrap(m, wrapped);
        }

        CryptographicOperations.ZeroMemory(kek);
        CryptographicOperations.ZeroMemory(m);
        return [.. SignatureEngine.Mpi(ephPoint), (byte)wrapped.Length, .. wrapped];
    }
}
