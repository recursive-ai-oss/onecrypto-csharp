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
        new Unwrap("checksum-unpadded-v6-key-bytes", padded: false, validity: false, control: false),
        new Unwrap("checksum-unpadded-v6-key-bytes-control", padded: false, validity: false, control: true),
        new Unwrap("checksum-padded-ecdh-key-bytes", padded: true, validity: false, control: false),
        new Unwrap("checksum-padded-ecdh-key-bytes-control", padded: true, validity: false, control: true),
        new Unwrap("checksum-padded-ecdh-bad-padding-vs-bad-checksum", padded: true, validity: true, control: false),
        new PkeskFailure("pkesk-rsa-bad-padding-vs-bad-checksum"),
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

    /// <summary>
    /// A public-key session-key packet addressed to an RSA key that cannot be unwrapped, two ways: the PKCS #1 padding is valid and the checksum is wrong
    /// (fixed class), or the padding is not valid at all (random class). Both end in the same null result, so what a caller sees must not tell them apart
    /// by time either (RFC 9580 §13.5). The RSA private-key operation is the platform's; this measures the unwrap call as the reader makes it.
    /// </summary>
    private sealed class PkeskFailure : TimingTarget
    {
        private readonly string _operation;
        private readonly PgpSecretKey _secret;
        private readonly PgpKey _public;
        private readonly RSA _rsa;
        private readonly int _modulusBytes;
        private PublicKeyEncryptedSessionKeyPacket[] _packets = [];

        public PkeskFailure(string operation)
        {
            _operation = operation;
            string root = Environment.GetEnvironmentVariable("ONECRYPTO_TESTDATA") ?? "testdata";
            PgpCertificate cert = PgpCertificate.Parse(File.ReadAllBytes(Path.Combine(root, "openpgp", "keys", "test-rsa3072.sec.asc")));
            _public = cert.Keys.First(static k => k.Packet is SecretKeyPacket && k.Packet.Algorithm is PublicKeyAlgorithm.Rsa or PublicKeyAlgorithm.RsaEncryptOnly);
            _ = PgpSecretKey.TryUnlock(_public, [], out PgpSecretKey? sk);
            _secret = sk ?? throw new InvalidOperationException("The test key could not be opened.");
            _rsa = RSA.Create();
            SignatureEngine.ImportPublicRsa(_rsa, _public.Packet.Material.Values[0].ToArray(), _public.Packet.Material.Values[1].ToArray());
            _modulusBytes = _public.Packet.Material.Values[0].Length;
        }

        public override string Primitive => "OpenPgpSessionKey";

        public override string Operation => _operation;

        public override void Prepare(ReadOnlySpan<TimingClass> classes)
        {
            if (_packets.Length < classes.Length)
            {
                _packets = new PublicKeyEncryptedSessionKeyPacket[classes.Length];
            }

            for (int i = 0; i < classes.Length; i++)
            {
                byte[] c;
                if (classes[i] == TimingClass.Fixed)
                {
                    // Valid padding around cipher || key || a checksum that is wrong.
                    byte[] m = new byte[1 + KeyLength + 2];
                    m[0] = (byte)RecursiveAI.OneCrypto.OpenPgp.Packets.SymmetricAlgorithm.Aes256;
                    RandomNumberGenerator.Fill(m.AsSpan(1));
                    c = _rsa.Encrypt(m, RSAEncryptionPadding.Pkcs1);
                }
                else
                {
                    c = RandomNumberGenerator.GetBytes(_modulusBytes);
                    c[0] = 0; // below the modulus, and not a valid padding
                }

                byte[] body = [3, .. _public.Packet.GetKeyId(), (byte)_public.Packet.Algorithm, .. SignatureEngine.Mpi(c)];
                _packets[i] = (PublicKeyEncryptedSessionKeyPacket)PacketParser.ParseAll(Packet.Create((byte)PacketTag.PublicKeyEncryptedSessionKey, body).ToArray())[0];
            }
        }

        public override void Run(int index) => s_sink += SessionKeys.Decrypt(_secret, _packets[index]) is null ? 0 : 1;
    }

    private sealed class Unwrap(string operation, bool padded, bool validity, bool control) : TimingTarget
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
                // Every message starts from fresh random bytes; the class blends the fixed key over them with a byte mask, not a branch, so both
                // classes run the same instructions in the untimed code and only the key value differs. The control forces the mask to zero
                // (both classes random): a control that flags points at the host or the harness, not the code under test.
                bool fixedClass = classes[i] == TimingClass.Fixed;
                byte[] key = new byte[KeyLength];
                FillKey(key, _fixed, classes[i], control);
                if (validity && !fixedClass)
                {
                    _fixed.CopyTo(key, 0);
                }

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
