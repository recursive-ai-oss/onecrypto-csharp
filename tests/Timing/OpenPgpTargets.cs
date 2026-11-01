using System.Buffers.Binary;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.OpenPgp;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace OneCrypto.Timing;

/// <summary>
/// The glue after a public-key unwrap of a session key: padding and checksum validation (RFC 9580 §5.1.3, §11.5, §13).
/// Key classes: the session key bytes are fixed against random, the message is always valid. Failure classes: both messages are
/// rejected, one for its padding and one for its checksum, so a caller cannot tell which check failed (RFC 9580 §13). A valid
/// message is not compared with a rejected one: success returns the key and failure does not, which the caller sees anyway.
/// </summary>
internal static class OpenPgpTargets
{
    private const int KeyLength = 32;

    // Written so the call cannot be optimised away.
    private static int s_sink;

    public static IEnumerable<TimingTarget> Targets() =>
    [
        new Unwrap("checksum-unpadded-v6-key-bytes", padded: false, validity: false),
        new Unwrap("checksum-padded-ecdh-key-bytes", padded: true, validity: false),
        new Unwrap("checksum-padded-ecdh-bad-padding-vs-bad-checksum", padded: true, validity: true),
        new Unlock("unlock-aead-v6-secret-bytes", version: 6),
        new Unlock("unlock-cfb-sha1-v4-secret-bytes", version: 4),
    ];

    /// <summary>
    /// Opening a protected secret key packet after the string-to-key (RFC 9580 §5.5.3): the HKDF and AEAD open (version 6) or the CFB decryption and SHA-1
    /// check (version 4). Key classes: the secret values are fixed against random, all sealed under the same derived key. The password hashing itself
    /// depends on the password by design and is not part of the claim.
    /// </summary>
    private sealed class Unlock(string operation, byte version) : TimingTarget
    {
        private static readonly byte[] Derived = RandomNumberGenerator.GetBytes(32);
        private readonly byte[] _fixed = RandomNumberGenerator.GetBytes(32);
        private readonly KeyPacket _public = PublicKeyPacket.Create(version, 0, PublicKeyAlgorithm.Ed25519, RandomNumberGenerator.GetBytes(32));
        private SecretKeyPacket[] _packets = [];

        public override string Primitive => "OpenPgpSecretKeyUnlock";

        public override string Operation => operation;

        public override void Prepare(ReadOnlySpan<TimingClass> classes)
        {
            if (_packets.Length < classes.Length)
            {
                _packets = new SecretKeyPacket[classes.Length];
            }

            for (int i = 0; i < classes.Length; i++)
            {
                byte[] secret = classes[i] == TimingClass.Fixed ? _fixed : RandomNumberGenerator.GetBytes(32);
                _packets[i] = SecretKeyWriter.Build(_public, secret, protect: true, (_, _) => (byte[])Derived.Clone());
            }
        }

        public override void Run(int index)
        {
            byte[]? plain = PgpSecretKey.OpenWithDerivedKey(_packets[index], Derived, 32);
            s_sink += plain?.Length ?? 0;
            if (plain is not null)
            {
                CryptographicOperations.ZeroMemory(plain);
            }
        }
    }

    private sealed class Unwrap(string operation, bool padded, bool validity) : TimingTarget
    {
        private readonly byte[] _fixed = RandomNumberGenerator.GetBytes(KeyLength);
        private readonly bool _padded = padded;
        private byte[][] _messages = [];

        public override string Primitive => "OpenPgpSessionKey";

        public override string Operation => operation;

        public override void Prepare(ReadOnlySpan<TimingClass> classes)
        {
            if (_messages.Length < classes.Length)
            {
                _messages = new byte[classes.Length][];
            }

            for (int i = 0; i < classes.Length; i++)
            {
                bool fixedClass = classes[i] == TimingClass.Fixed;
                byte[] key = validity || fixedClass ? _fixed : RandomNumberGenerator.GetBytes(KeyLength);
                byte[] m = Build(key, _padded);
                if (validity)
                {
                    if (fixedClass)
                    {
                        m[^1] ^= 0x5A; // wrong padding, right checksum
                    }
                    else
                    {
                        m[KeyLength] ^= 0x5A; // right padding, wrong checksum
                    }
                }

                _messages[i] = m;
            }
        }

        public override void Run(int index) => s_sink += SessionKeys.FromChecksummed(_messages[index], v3: false, padded: _padded)?.Key.Length ?? 0;

        private static byte[] Build(byte[] key, bool padded)
        {
            int len = key.Length + 2;
            int pad = padded ? 8 - (len % 8) : 0;
            byte[] m = new byte[len + pad];
            key.CopyTo(m, 0);
            ushort sum = 0;
            foreach (byte b in key)
            {
                sum += b;
            }

            BinaryPrimitives.WriteUInt16BigEndian(m.AsSpan(key.Length), sum);
            for (int i = 0; i < pad; i++)
            {
                m[len + i] = (byte)pad;
            }

            return m;
        }
    }
}
