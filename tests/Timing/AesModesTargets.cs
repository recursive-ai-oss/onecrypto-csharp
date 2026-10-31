using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Timing;

/// <summary>
/// Timing targets for the secret-handling glue of the AES modes: decryption (and unwrapping) of valid messages.
/// Two kinds (plus A/A controls for the key kind), each with the fixed class against a fresh random one:
/// <list type="bullet">
/// <item>data: the key is fixed, the plaintext (or key data) is the secret;</item>
/// <item>key: the message is fixed, the key is the secret. Building a key object is not part of what is timed, so each class draws a
/// key object at random from its own half of a pool of 2 x <see cref="PoolSize"/> objects, the halves interleaved slot by slot: every
/// object of the fixed class holds the same key, every object of the random class holds its own. Both classes thus touch equally many distinct, equally cold objects, and only the key
/// value differs; a single shared object for the fixed class would make it cache-hot and show a difference that is not the key.</item>
/// </list>
/// The sizes are chosen so one is a few blocks with a partial last block and one crosses the internal batch boundary.
/// </summary>
internal static class AesModesTargets
{
    private const int PoolSize = 128;

    public static IEnumerable<TimingTarget> Targets() =>
    [
        new AeadData("AES-OCB", "decrypt-data-40B", 40, 15, key => new OcbMode(key)),
        new AeadData("AES-OCB", "decrypt-data-2100B", 2100, 15, key => new OcbMode(key)),
        new AeadKey("AES-OCB", "decrypt-key-40B", 40, 15, key => new OcbMode(key)),
        new AeadData("AES-EAX", "decrypt-data-40B", 40, 16, key => new EaxMode(key)),
        new AeadData("AES-EAX", "decrypt-data-2100B", 2100, 16, key => new EaxMode(key)),
        new AeadKey("AES-EAX", "decrypt-key-40B", 40, 16, key => new EaxMode(key)),
        new WrapData(),
        new WrapKey(),
        // A/A controls: both classes use distinct random keys, so any flagged difference is the harness or the machine, not the key.
        new AeadKey("AES-EAX", "control-key-40B", 40, 16, key => new EaxMode(key), control: true),
        new WrapKey("control-key-32B", control: true),
    ];

    private abstract class Mode : IDisposable
    {
        public void Dispose()
        {
            Release();
            GC.SuppressFinalize(this);
        }

        public abstract void Encrypt(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[] aad);

        public abstract bool Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] aad);

        public abstract void Release();
    }

    private sealed class OcbMode(byte[] key) : Mode
    {
        private readonly AesOcb _ocb = new(key);

        public override void Encrypt(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[] aad) => _ocb.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        public override bool Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] aad) => _ocb.TryDecrypt(nonce, ciphertext, tag, plaintext, aad);

        public override void Release() => _ocb.Dispose();
    }

    private sealed class EaxMode(byte[] key) : Mode
    {
        private readonly AesEax _eax = new(key);

        public override void Encrypt(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[] aad) => _eax.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        public override bool Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] aad) => _eax.TryDecrypt(nonce, ciphertext, tag, plaintext, aad);

        public override void Release() => _eax.Dispose();
    }

    /// <summary>Same key and nonce every call; the plaintext is the secret.</summary>
    private sealed class AeadData(string primitive, string operation, int size, int nonceSize, Func<byte[], Mode> create) : TimingTarget
    {
        private readonly byte[] _nonce = RandomNumberGenerator.GetBytes(nonceSize);
        private readonly byte[] _aad = RandomNumberGenerator.GetBytes(13);
        private readonly byte[] _fixedPlain = RandomNumberGenerator.GetBytes(size);
        private readonly Mode _mode = create(RandomNumberGenerator.GetBytes(16));
        private readonly byte[] _sinkOut = new byte[size];
        private byte[][] _ct = [];
        private byte[][] _tag = [];
        private bool _sink;

        public override string Primitive => primitive;

        public override string Operation => operation;

        public override void Prepare(ReadOnlySpan<TimingClass> classes)
        {
            if (_ct.Length < classes.Length)
            {
                _ct = new byte[classes.Length][];
                _tag = new byte[classes.Length][];
                for (int i = 0; i < _ct.Length; i++)
                {
                    _ct[i] = new byte[size];
                    _tag[i] = new byte[16];
                }
            }

            byte[] plain = new byte[size];
            for (int i = 0; i < classes.Length; i++)
            {
                if (classes[i] == TimingClass.Fixed)
                {
                    _fixedPlain.CopyTo(plain, 0);
                }
                else
                {
                    RandomNumberGenerator.Fill(plain);
                }

                _mode.Encrypt(_nonce, plain, _ct[i], _tag[i], _aad);
            }
        }

        public override void Run(int index) => _sink ^= _mode.Decrypt(_nonce, _ct[index], _tag[index], _sinkOut, _aad);
    }

    /// <summary>Same message every call; the key is the secret.</summary>
    private sealed class AeadKey(string primitive, string operation, int size, int nonceSize, Func<byte[], Mode> create, bool control = false) : TimingTarget
    {
        private readonly byte[] _nonce = RandomNumberGenerator.GetBytes(nonceSize);
        private readonly byte[] _aad = RandomNumberGenerator.GetBytes(13);
        private readonly byte[] _plain = RandomNumberGenerator.GetBytes(size);
        private readonly byte[] _sinkOut = new byte[size];
        private readonly byte[] _fixedKey = RandomNumberGenerator.GetBytes(16);
        private readonly Mode[] _modes = new Mode[2 * PoolSize];
        private readonly byte[][] _ct = new byte[2 * PoolSize][];
        private readonly byte[][] _tag = new byte[2 * PoolSize][];
        private int[] _pick = [];
        private bool _sink;

        public override string Primitive => primitive;

        public override string Operation => operation;

        public override void Prepare(ReadOnlySpan<TimingClass> classes)
        {
            // Even slots hold the fixed key, odd slots distinct random keys, so the two classes are interleaved in memory.
            for (int k = 0; k < 2 * PoolSize; k++)
            {
                _modes[k]?.Release();
                _modes[k] = create(k % 2 == 0 && !control ? _fixedKey : RandomNumberGenerator.GetBytes(16));
                _ct[k] = new byte[size];
                _tag[k] = new byte[16];
                _modes[k].Encrypt(_nonce, _plain, _ct[k], _tag[k], _aad);
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

        public override void Run(int index)
        {
            int k = _pick[index];
            _sink ^= _modes[k].Decrypt(_nonce, _ct[k], _tag[k], _sinkOut, _aad);
        }
    }

    /// <summary>Same key-encryption key every call; the wrapped key data is the secret.</summary>
    private sealed class WrapData : TimingTarget
    {
        private readonly AesKeyWrap[] _kw = [new(RandomNumberGenerator.GetBytes(32))];
        private readonly byte[] _fixedData = RandomNumberGenerator.GetBytes(32);
        private readonly byte[] _out = new byte[32];
        private byte[][] _wrapped = [];
        private bool _sink;

        public override string Primitive => "AES-KW";

        public override string Operation => "unwrap-data-32B";

        public override void Prepare(ReadOnlySpan<TimingClass> classes)
        {
            if (_wrapped.Length < classes.Length)
            {
                _wrapped = new byte[classes.Length][];
                for (int i = 0; i < _wrapped.Length; i++)
                {
                    _wrapped[i] = new byte[40];
                }
            }

            for (int i = 0; i < classes.Length; i++)
            {
                _kw[0].Wrap(classes[i] == TimingClass.Fixed ? _fixedData : RandomNumberGenerator.GetBytes(32), _wrapped[i]);
            }
        }

        public override void Run(int index) => _sink ^= _kw[0].TryUnwrap(_wrapped[index], _out);
    }

    /// <summary>Same wrapped message every call; the key-encryption key is the secret.</summary>
    private sealed class WrapKey(string operation = "unwrap-key-32B", bool control = false) : TimingTarget
    {
        private readonly byte[] _data = RandomNumberGenerator.GetBytes(32);
        private readonly byte[] _fixedKek = RandomNumberGenerator.GetBytes(32);
        private readonly AesKeyWrap[] _kws = new AesKeyWrap[2 * PoolSize];
        private readonly byte[][] _wrapped = new byte[2 * PoolSize][];
        private readonly byte[] _out = new byte[32];
        private int[] _pick = [];
        private bool _sink;

        public override string Primitive => "AES-KW";

        public override string Operation => operation;

        public override void Prepare(ReadOnlySpan<TimingClass> classes)
        {
            for (int k = 0; k < 2 * PoolSize; k++)
            {
                _kws[k]?.Dispose();
                _kws[k] = new AesKeyWrap(k % 2 == 0 && !control ? _fixedKek : RandomNumberGenerator.GetBytes(32));
                _wrapped[k] = new byte[40];
                _kws[k].Wrap(_data, _wrapped[k]);
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

        public override void Run(int index)
        {
            int k = _pick[index];
            _sink ^= _kws[k].TryUnwrap(_wrapped[k], _out);
        }
    }
}
