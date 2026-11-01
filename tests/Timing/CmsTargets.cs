using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace OneCrypto.Timing;

/// <summary>
/// The padding check after CBC decryption of CMS content (RFC 5652 §6.3; RFC 3218 §2.3). Both classes are rejected messages, so the outcome is the same and
/// the time must not depend on how the last block is wrong: the fixed class is one octet short of valid padding (every pad octet right but one, the
/// slowest case for an early-exit compare), the random class has a random last block. A valid message is not compared with a rejected one: success returns
/// the plaintext and failure does not, which the caller sees anyway.
/// </summary>
internal static class CmsTargets
{
    private static int s_sink;

    public static IEnumerable<TimingTarget> Targets() => [new CbcPadding("cbc-bad-padding-shape")];

    private sealed class CbcPadding(string operation) : TimingTarget
    {
        private const int Blocks = 3;
        private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
        private readonly byte[] _iv = RandomNumberGenerator.GetBytes(16);
        private readonly ContentCipher _cipher = CmsCiphers.Require(CmsOids.Aes256Cbc);
        private byte[][] _messages = [];

        public override string Primitive => "CmsCbc";

        public override string Operation => operation;

        public override void Prepare(ReadOnlySpan<TimingClass> classes)
        {
            if (_messages.Length < classes.Length)
            {
                _messages = new byte[classes.Length][];
            }

            using Aes aes = Aes.Create();
            aes.Key = _key;
            for (int i = 0; i < classes.Length; i++)
            {
                byte[] plain = RandomNumberGenerator.GetBytes(16 * Blocks);
                if (classes[i] == TimingClass.Fixed)
                {
                    // 16 octets of 0x10 would be a whole block of valid padding; one wrong octet in the middle makes it invalid after 8 right ones.
                    plain.AsSpan(16 * (Blocks - 1)).Fill(0x10);
                    plain[(16 * (Blocks - 1)) + 7] = 0x77;
                }
                else
                {
                    // A random last block, whose final octet is moved out of the 1..16 range so that it is rejected too.
                    plain[^1] = (byte)(0x20 | (plain[^1] & 0xDF));
                }

                _messages[i] = aes.EncryptCbc(plain, _iv, PaddingMode.None);
            }
        }

        public override void Run(int index) => s_sink += CmsCiphers.TryDecryptCbc(_cipher, _key, _iv, _messages[index], out byte[] p) ? p.Length : 0;
    }
}
