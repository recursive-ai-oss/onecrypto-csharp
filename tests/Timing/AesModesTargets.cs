using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Timing;

/// <summary>
/// Timing targets for the secret-handling glue of the AES modes: decryption (and unwrapping) of valid messages.
/// Two kinds (plus A/A controls for the key kind), each with the fixed class against a fresh random one:
/// <list type="bullet">
/// <item>data: the key is fixed, the plaintext (or key data) is the secret;</item>
/// <item>key: the message is fixed, the key is the secret. A fresh key object is built for every call in the untimed
/// <see cref="TimingTarget.Before"/> hook, by identical code in both classes, so the classes differ in nothing but the key value.</item>
/// </list>
/// The sizes are chosen so one is a few blocks with a partial last block and one crosses the internal batch boundary.
/// </summary>
internal static class AesModesTargets
{
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
        new AeadKey("AES-OCB", "control-key-40B", 40, 15, key => new OcbMode(key), control: true),
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

    /// <summary>
    /// Same message every call; the key is the secret. The key object and the ciphertext under it are built per call in the untimed
    /// <see cref="Before"/> hook, by the same code in both classes; only the key value differs.
    /// </summary>
    private sealed class AeadKey(string primitive, string operation, int size, int nonceSize, Func<byte[], Mode> create, bool control = false) : TimingTarget
    {
        private readonly byte[] _nonce = RandomNumberGenerator.GetBytes(nonceSize);
        private readonly byte[] _aad = RandomNumberGenerator.GetBytes(13);
        private readonly byte[] _plain = RandomNumberGenerator.GetBytes(size);
        private readonly byte[] _sinkOut = new byte[size];
        private readonly byte[] _fixedKey = RandomNumberGenerator.GetBytes(16);
        private readonly byte[] _key = new byte[16];
        private readonly byte[] _ct = new byte[size];
        private readonly byte[] _tag = new byte[16];
        private TimingClass[] _classes = [];
        private Mode? _mode;
        private bool _sink;

        public override string Primitive => primitive;

        public override string Operation => operation;

        public override void Prepare(ReadOnlySpan<TimingClass> classes) => _classes = classes.ToArray();

        public override void Before(int index)
        {
            _mode?.Release();
            FillKey(_key, _fixedKey, _classes[index], control);

            _mode = create(_key);
            _mode.Encrypt(_nonce, _plain, _ct, _tag, _aad);
        }

        public override void Run(int index) => _sink ^= _mode!.Decrypt(_nonce, _ct, _tag, _sinkOut, _aad);
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

    /// <summary>Same wrapped message every call; the key-encryption key is the secret, set up per call in the untimed <see cref="Before"/> hook.</summary>
    private sealed class WrapKey(string operation = "unwrap-key-32B", bool control = false) : TimingTarget, IDisposable
    {
        private readonly byte[] _data = RandomNumberGenerator.GetBytes(32);
        private readonly byte[] _fixedKek = RandomNumberGenerator.GetBytes(32);
        private readonly byte[] _kek = new byte[32];
        private readonly byte[] _wrapped = new byte[40];
        private readonly byte[] _out = new byte[32];
        private TimingClass[] _classes = [];
        private AesKeyWrap? _kw;
        private bool _sink;

        public override string Primitive => "AES-KW";

        public override string Operation => operation;

        public override void Prepare(ReadOnlySpan<TimingClass> classes) => _classes = classes.ToArray();

        public override void Before(int index)
        {
            _kw?.Dispose();
            FillKey(_kek, _fixedKek, _classes[index], control);

            _kw = new AesKeyWrap(_kek);
            _kw.Wrap(_data, _wrapped);
        }

        public override void Run(int index) => _sink ^= _kw!.TryUnwrap(_wrapped, _out);

        public void Dispose() => _kw?.Dispose();
    }
}
