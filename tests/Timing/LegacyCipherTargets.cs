using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Timing;

/// <summary>
/// Timing targets for Camellia and the decrypt-only legacy ciphers. Per cipher, three kinds (and an A/A control for the key kind):
/// <list type="bullet">
/// <item>data: the key is fixed and the input blocks are the secret (the fixed class reuses one block set, the random class draws a new one);</item>
/// <item>key: the input blocks are fixed and the key is the secret. Building a key object is not timed, so each class draws an object from
/// its own half of a pool of 2 x <see cref="PoolSize"/> objects, interleaved slot by slot, which keeps the two classes equally cold;</item>
/// <item>key setup: the key schedule itself, with the key as the secret (it allocates, which the percentile cropping absorbs).</item>
/// </list>
/// The operation is ECB over a few blocks: the cost and the secret-dependent accesses are in the block function, and the modes only
/// XOR public chaining values.
/// </summary>
internal static class LegacyCipherTargets
{
    private const int PoolSize = 128;
    private const int Blocks = 4;

    /// <summary>A keyed cipher and the one operation under test.</summary>
    private sealed class Op(Action<byte[], byte[]> run, IDisposable owner) : IDisposable
    {
        public void Run(byte[] input, byte[] output) => run(input, output);

        public void Dispose() => owner.Dispose();
    }

    private sealed record Cipher(string Name, int KeyLength, int BlockSize, bool CanEncrypt, Func<byte[], Op> Decrypting, Func<byte[], Op>? Encrypting);

    private static Cipher[] Ciphers() =>
    [
        new("Camellia-128", 16, 16, true, k => Make(new Camellia(k), (c, i, o) => c.DecryptEcb(i, o)), k => Make(new Camellia(k), (c, i, o) => c.EncryptEcb(i, o))),
        new("Camellia-256", 32, 16, true, k => Make(new Camellia(k), (c, i, o) => c.DecryptEcb(i, o)), k => Make(new Camellia(k), (c, i, o) => c.EncryptEcb(i, o))),
        new("CAST5", 16, 8, false, k => Make(new Cast5(k), (c, i, o) => c.DecryptEcb(i, o)), null),
        new("IDEA", 16, 8, false, k => Make(new Idea(k), (c, i, o) => c.DecryptEcb(i, o)), null),
        new("Blowfish", 16, 8, false, k => Make(new Blowfish(k), (c, i, o) => c.DecryptEcb(i, o)), null),
        new("Twofish-128", 16, 16, false, k => Make(new Twofish(k), (c, i, o) => c.DecryptEcb(i, o)), null),
        new("Twofish-256", 32, 16, false, k => Make(new Twofish(k), (c, i, o) => c.DecryptEcb(i, o)), null),
    ];

    private static Op Make<T>(T cipher, Action<T, byte[], byte[]> run)
        where T : IDisposable => new((i, o) => run(cipher, i, o), cipher);

    public static IEnumerable<TimingTarget> Targets()
    {
        foreach (Cipher c in Ciphers())
        {
            yield return new DataTarget(c, "decrypt-data", c.Decrypting);
            yield return new KeyTarget(c, "decrypt-key", c.Decrypting, control: false);
            if (c.Encrypting is not null)
            {
                yield return new DataTarget(c, "encrypt-data", c.Encrypting);
                yield return new KeyTarget(c, "encrypt-key", c.Encrypting, control: false);
            }

            yield return new KeySetupTarget(c);
        }

        // A/A control: both classes use distinct random keys, so a flagged difference is the harness or the machine.
        yield return new KeyTarget(Ciphers()[0], "control-key", Ciphers()[0].Decrypting, control: true);
    }

    private sealed class DataTarget(Cipher c, string operation, Func<byte[], Op> create) : TimingTarget
    {
        private readonly Op _op = create(RandomNumberGenerator.GetBytes(c.KeyLength));
        private readonly byte[] _fixedInput = RandomNumberGenerator.GetBytes(Blocks * c.BlockSize);
        private readonly byte[] _out = new byte[Blocks * c.BlockSize];
        private byte[][] _inputs = [];

        public override string Primitive => c.Name;

        public override string Operation => operation;

        public override void Prepare(ReadOnlySpan<TimingClass> classes)
        {
            if (_inputs.Length < classes.Length)
            {
                _inputs = new byte[classes.Length][];
                for (int i = 0; i < _inputs.Length; i++)
                {
                    _inputs[i] = new byte[Blocks * c.BlockSize];
                }
            }

            for (int i = 0; i < classes.Length; i++)
            {
                if (classes[i] == TimingClass.Fixed)
                {
                    _fixedInput.CopyTo(_inputs[i], 0);
                }
                else
                {
                    RandomNumberGenerator.Fill(_inputs[i]);
                }
            }
        }

        public override void Run(int index) => _op.Run(_inputs[index], _out);
    }

    private sealed class KeyTarget(Cipher c, string operation, Func<byte[], Op> create, bool control) : TimingTarget
    {
        private readonly byte[] _input = RandomNumberGenerator.GetBytes(Blocks * c.BlockSize);
        private readonly byte[] _fixedKey = RandomNumberGenerator.GetBytes(c.KeyLength);
        private readonly byte[] _out = new byte[Blocks * c.BlockSize];
        private readonly Op?[] _ops = new Op?[2 * PoolSize];
        private int[] _pick = [];

        public override string Primitive => c.Name;

        public override string Operation => operation;

        public override void Prepare(ReadOnlySpan<TimingClass> classes)
        {
            for (int k = 0; k < _ops.Length; k++)
            {
                _ops[k]?.Dispose();
                _ops[k] = create(k % 2 == 0 && !control ? _fixedKey : RandomNumberGenerator.GetBytes(c.KeyLength));
            }

            if (_pick.Length < classes.Length)
            {
                _pick = new int[classes.Length];
            }

            for (int i = 0; i < classes.Length; i++)
            {
                _pick[i] = (2 * RandomNumberGenerator.GetInt32(PoolSize)) + (classes[i] == TimingClass.Fixed ? 0 : 1);
            }
        }

        public override void Run(int index) => _ops[_pick[index]]!.Run(_input, _out);
    }

    private sealed class KeySetupTarget(Cipher c) : TimingTarget
    {
        private readonly byte[] _fixedKey = RandomNumberGenerator.GetBytes(c.KeyLength);
        private byte[][] _keys = [];

        public override string Primitive => c.Name;

        public override string Operation => "key-setup";

        public override void Prepare(ReadOnlySpan<TimingClass> classes)
        {
            if (_keys.Length < classes.Length)
            {
                _keys = new byte[classes.Length][];
                for (int i = 0; i < _keys.Length; i++)
                {
                    _keys[i] = new byte[c.KeyLength];
                }
            }

            for (int i = 0; i < classes.Length; i++)
            {
                if (classes[i] == TimingClass.Fixed)
                {
                    _fixedKey.CopyTo(_keys[i], 0);
                }
                else
                {
                    RandomNumberGenerator.Fill(_keys[i]);
                }
            }
        }

        public override void Run(int index) => c.Decrypting(_keys[index]).Dispose();
    }
}
