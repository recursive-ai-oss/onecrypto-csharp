using System.Buffers.Binary;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.OpenPgp;

namespace OneCrypto.Timing;

/// <summary>
/// The glue after a public-key unwrap of a session key: padding and checksum validation (RFC 9580 §5.1.3, §11.5, §13).
/// Key classes: the session key bytes are fixed against random, the message is always valid. Validity classes: a valid message
/// against one whose padding and checksum are both wrong, same length, to show that failure takes the same time as success.
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
        new Unwrap("checksum-padded-ecdh-valid-vs-invalid", padded: true, validity: true),
    ];

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
                byte[] key = validity ? _fixed : (fixedClass ? _fixed : RandomNumberGenerator.GetBytes(KeyLength));
                byte[] m = Build(key, _padded);
                if (validity && !fixedClass)
                {
                    RandomNumberGenerator.Fill(m); // wrong padding and wrong checksum, same length
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
