using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.Primitives.Internal;

namespace OneCrypto.Timing;

/// <summary>
/// Timing targets for Camellia and the decrypt-only legacy ciphers. Per cipher, three kinds (and an A/A control for the key kind):
/// <list type="bullet">
/// <item>data: the key is fixed and the input blocks are the secret (the fixed class reuses one block set, the random class draws a new one);</item>
/// <item>key: the input blocks are fixed and the key is the secret. A fresh key object is built for every call in the untimed
/// <see cref="TimingTarget.Before"/> hook, by identical code in both classes, so only the key value differs;</item>
/// <item>key setup: the key schedule itself, with the key as the secret (it allocates, which the percentile cropping absorbs).</item>
/// </list>
/// The operation is ECB over a few blocks: the cost and the secret-dependent accesses are in the block function, and the modes only
/// XOR public chaining values.
/// </summary>
internal static class LegacyCipherTargets
{
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

    /// <summary>Hashes the key with the platform's SHA-256 (no secret-dependent timing) and keeps the digest in a pinned buffer, as a key
    /// schedule keeps its words: the same shape of work as a key setup, with no cipher code in it.</summary>
    private sealed class HashedKey : IDisposable
    {
        private readonly byte[] _state = GC.AllocateUninitializedArray<byte>(32, pinned: true);

        public HashedKey(byte[] key) => SHA256.HashData(key, _state);

        public void Dispose() => CryptographicOperations.ZeroMemory(_state);
    }

    /// <summary>Runs the instruction mix of a vector key schedule (byte shuffles, the AES last round, shifts and XORs, a masked
    /// carry-less GF(2^8) multiply) over the key with no cipher in it. Every instruction has operand-independent latency, so a flag
    /// here would say the processor, not the cipher code, makes the timing depend on the key bytes.</summary>
    private sealed class VectorMixKey : IDisposable
    {
        private readonly byte[] _state = GC.AllocateUninitializedArray<byte>(16, pinned: true);

        public VectorMixKey(byte[] key)
        {
            Vector128<byte> v = Vector128.Create(key);
            Vector128<byte> table = Vector128.Create((byte)0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76);
            uint acc = 1;
            for (int round = 0; round < 24; round++)
            {
                v = ByteShuffle.Lookup(table, v & Vector128.Create((byte)0x0F));
                v ^= Vector128.ShiftLeft(v, 1) ^ (Vector128.Create((byte)0x1B) & Vector128.LessThan(v.AsSByte(), Vector128<sbyte>.Zero).AsByte());
                if (ByteShuffle.HasAesRound)
                {
                    v = ByteShuffle.AesRound(v);
                }

                uint b = v.AsUInt32().GetElement(0);
                uint a = acc & 0xFF;
                uint r = 0;
                for (int i = 0; i < 8; i++)
                {
                    r ^= a & (0u - ((b >> i) & 1));
                    a = (a << 1) ^ (0x14Du & (0u - (a >> 7)));
                }

                acc = (acc * 0x01000193u) ^ r ^ b;
            }

            v.CopyTo(_state);
            _state[0] ^= (byte)acc;
        }

        public void Dispose() => CryptographicOperations.ZeroMemory(_state);
    }

    private static readonly Cipher VectorControl = new("VectorControl", 16, 16, false, k => Make(new VectorMixKey(k), (_, _, _) => { }), null);

    // Camellia's key schedule without the AES-instruction S-box (the blended-table path), to tell the instruction apart from the rest of the schedule.
    private static readonly Cipher CamelliaNoAes = new("CamelliaNoAes-128", 16, 16, false, k => Make(new CamelliaEngine(k, false), (_, _, _) => { }), null);

    private static readonly Cipher HashControl = new("HashControl", 16, 16, false, k => Make(new HashedKey(k), (_, _, _) => { }), null);

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

            yield return new KeySetupTarget(c, KeySetupMode.FixedVsRandom);
        }

        // Harness control: a constant-time operation of ours that is not a cipher, run through the same key-setup modes. A flag here is the
        // machine or the harness, never a cipher's key schedule.
        foreach (KeySetupMode mode in Enum.GetValues<KeySetupMode>())
        {
            yield return new KeySetupTarget(HashControl, mode);
            yield return new KeySetupTarget(VectorControl, mode);
            yield return new KeySetupTarget(CamelliaNoAes, mode);
        }

        // The platform's zeroing of a pinned buffer holding key-derived words, with no cipher involved: the buffer sizes a key schedule
        // wipes. Fixed class: every byte 0 or 1; random class: uniform bytes (an A/A control when both are uniform).
        foreach (int size in new[] { 208, 416 })
        {
            yield return new WipeTarget(size, lowBits: true);
            yield return new WipeTarget(size, lowBits: false);
        }

        // A/A controls, one per key kind: both classes use distinct random keys, so a flagged difference is the harness or the machine.
        foreach (Cipher c in Ciphers())
        {
            yield return new KeySetupTarget(c, KeySetupMode.RandomVsRandom);
            yield return new KeySetupTarget(c, KeySetupMode.FixedVsFixed);
            yield return new KeySetupTarget(c, KeySetupMode.FixedVsFixedSwapped);
            yield return new KeySetupTarget(c, KeySetupMode.LowBitsVsRandom);
            yield return new KeyTarget(c, "control-decrypt-key", c.Decrypting, control: true);
            yield return new DataTarget(c, "control-decrypt-data", c.Decrypting, control: true);
            yield return new DataTarget(c, "pair-decrypt-data", c.Decrypting, pair: true);
            if (c.Name == "IDEA")
            {
                // Sixteen times the work per call: a difference made by the cipher grows with it, one made by the harness or the
                // machine stays the same size and sinks into the larger total.
                yield return new DataTarget(c, "decrypt-data-x16", c.Decrypting, blocks: 16 * Blocks);
                yield return new DataTarget(c, "control-decrypt-data-x16", c.Decrypting, control: true, blocks: 16 * Blocks);
            }
            if (c.Encrypting is not null)
            {
                yield return new KeyTarget(c, "control-encrypt-key", c.Encrypting, control: true);
                yield return new DataTarget(c, "control-encrypt-data", c.Encrypting, control: true);
            }
        }
    }

    private sealed class DataTarget(Cipher c, string operation, Func<byte[], Op> create, bool control = false, bool pair = false, int blocks = Blocks) : TimingTarget
    {
        private readonly byte[] _otherInput = RandomNumberGenerator.GetBytes(blocks * c.BlockSize);
        private readonly Op _op = create(RandomNumberGenerator.GetBytes(c.KeyLength));
        private readonly byte[] _fixedInput = RandomNumberGenerator.GetBytes(blocks * c.BlockSize);
        private readonly byte[] _out = new byte[blocks * c.BlockSize];
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
                    _inputs[i] = new byte[blocks * c.BlockSize];
                }
            }

            // Same instructions in both classes (random fill, fixed value blended in by a byte mask); the control blends nothing.
            for (int i = 0; i < classes.Length; i++)
            {
                if (pair)
                {
                    FillPair(_inputs[i], _fixedInput, _otherInput, classes[i]);
                }
                else
                {
                    FillKey(_inputs[i], _fixedInput, classes[i], control);
                }
            }
        }

        public override void Run(int index) => _op.Run(_inputs[index], _out);
    }

    /// <summary>
    /// The key is the secret. For every call the harness builds a fresh key object in the untimed <see cref="Before"/> hook: the same
    /// allocation, the same random-number call and the same key schedule code run in both classes, and the fixed class only has the fixed
    /// key copied over the random bytes before the object is built. Nothing but the key value differs between the classes, and the
    /// A/A control (both classes random) must therefore pass.
    /// </summary>
    private sealed class KeyTarget(Cipher c, string operation, Func<byte[], Op> create, bool control) : TimingTarget
    {
        private readonly byte[] _input = RandomNumberGenerator.GetBytes(Blocks * c.BlockSize);
        private readonly byte[] _fixedKey = RandomNumberGenerator.GetBytes(c.KeyLength);
        private readonly byte[] _key = new byte[c.KeyLength];
        private readonly byte[] _out = new byte[Blocks * c.BlockSize];
        private TimingClass[] _classes = [];
        private Op? _op;

        public override string Primitive => c.Name;

        public override string Operation => operation;

        public override void Prepare(ReadOnlySpan<TimingClass> classes) => _classes = classes.ToArray();

        public override void Before(int index)
        {
            _op?.Dispose();
            FillKey(_key, _fixedKey, _classes[index], control);

            _op = create(_key);
        }

        public override void Run(int index) => _op!.Run(_input, _out);
    }

    /// <summary>Times <see cref="CryptographicOperations.ZeroMemory"/> on a pinned buffer whose contents are filled, untimed, per class.</summary>
    private sealed class WipeTarget(int size, bool lowBits) : TimingTarget
    {
        private readonly byte[] _buffer = GC.AllocateUninitializedArray<byte>(size, pinned: true);
        private readonly byte[] _scratch = new byte[size];
        private TimingClass[] _classes = [];

        public override string Primitive => "Wipe";

        public override string Operation => FormattableString.Invariant($"zero-{size}B-{(lowBits ? "lowbits" : "control")}");

        public override void Prepare(ReadOnlySpan<TimingClass> classes) => _classes = classes.ToArray();

        public override void Before(int index)
        {
            RandomNumberGenerator.Fill(_scratch);
            // Fixed (0) -> keep 0x01, Random (1) -> keep 0xFF; the control keeps everything in both classes. A mask, not a branch.
            byte keep = (byte)(0xFF ^ (((int)_classes[index] - 1) & 0xFE & (lowBits ? 0xFF : 0)));
            for (int i = 0; i < _scratch.Length; i++)
            {
                _buffer[i] = (byte)(_scratch[i] & keep);
            }
        }

        public override void Run(int index) => CryptographicOperations.ZeroMemory(_buffer);
    }

    /// <summary>What the two classes of a key-setup target are.</summary>
    private enum KeySetupMode
    {
        /// <summary>The leak test: one fixed key against fresh random keys.</summary>
        FixedVsRandom,

        /// <summary>A/A control: fresh random keys in both classes.</summary>
        RandomVsRandom,

        /// <summary>Two different fixed keys, each repeated in its class. A key-dependent time would show here as it does against random keys,
        /// while an effect of seeing the same bytes again and again is in both classes and cancels.</summary>
        FixedVsFixed,

        /// <summary>Fresh keys in both classes, no key repeated: every byte of the first class's keys is 0 or 1, the other class's keys are
        /// uniformly random. A time that depends on the key's value shows here without any repeated input.</summary>
        LowBitsVsRandom,

        /// <summary>The pair test with the two keys' roles exchanged. If the flag follows the key it is the key's effect on the
        /// measurement; if it stays with the class it is the harness.</summary>
        FixedVsFixedSwapped,
    }

    private sealed class KeySetupTarget(Cipher c, KeySetupMode mode) : TimingTarget
    {
        private readonly byte[] _fixedKey = RandomNumberGenerator.GetBytes(c.KeyLength);
        private readonly byte[] _otherFixedKey = RandomNumberGenerator.GetBytes(c.KeyLength);
        private byte[][] _keys = [];

        public override string Primitive => c.Name;

        public override string Operation => mode switch
        {
            KeySetupMode.FixedVsRandom => "key-setup",
            KeySetupMode.RandomVsRandom => "control-key-setup",
            KeySetupMode.FixedVsFixed => "pair-key-setup",
            KeySetupMode.FixedVsFixedSwapped => "pair-swapped-key-setup",
            _ => "lowbits-key-setup",
        };

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

            // The fixed key is blended in with a byte mask, not an if: both classes run the same instructions before the timed call.
            // The control (mask zero) makes both classes random, so a flag there is the harness or the machine.
            for (int i = 0; i < classes.Length; i++)
            {
                if (mode == KeySetupMode.LowBitsVsRandom)
                {
                    // Random bytes, then (for the low-bits class) only the low bit kept, by a mask: both classes run the same instructions.
                    RandomNumberGenerator.Fill(_keys[i]);
                    byte keep = (byte)(0xFF ^ (((int)classes[i] - 1) & 0xFE)); // Fixed (0) -> 0x01, Random (1) -> 0xFF
                    for (int b = 0; b < _keys[i].Length; b++)
                    {
                        _keys[i][b] &= keep;
                    }
                }
                else if (mode is KeySetupMode.FixedVsFixed or KeySetupMode.FixedVsFixedSwapped)
                {
                    byte[] first = mode == KeySetupMode.FixedVsFixed ? _fixedKey : _otherFixedKey;
                    byte[] second = mode == KeySetupMode.FixedVsFixed ? _otherFixedKey : _fixedKey;
                    byte mask = (byte)(((int)classes[i] - 1) & 0xFF); // Fixed (0) -> 0xFF
                    for (int b = 0; b < _keys[i].Length; b++)
                    {
                        _keys[i][b] = (byte)((first[b] & mask) | (second[b] & ~mask));
                    }
                }
                else
                {
                    FillKey(_keys[i], _fixedKey, classes[i], mode == KeySetupMode.RandomVsRandom);
                }
            }
        }

        // The previous object is wiped in the untimed hook, so the timed call is the key schedule alone. Wiping overwrites key-derived
        // words with zeros through the platform's memset, whose time on some processors depends on what it overwrites; that is
        // measured separately by the wipe targets.
        public override void Before(int index)
        {
            _previous?.Dispose();
            _previous = null;
        }

        private Op? _previous;

        public override void Run(int index) => _previous = c.Decrypting(_keys[index]);
    }
}
