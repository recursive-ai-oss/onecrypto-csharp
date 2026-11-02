using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Primitives.Fallback;

namespace OneCrypto.Timing;

/// <summary>
/// Timing targets for the managed fallbacks that handle secrets: the Keccak sponge (SHA-3 and SHAKE of a secret, as when it hashes a
/// seed or key) and ChaCha20-Poly1305 (secret key, and secret plaintext). Verify-only RSA and ECDSA touch no secrets and have no
/// target. The sponge and the cipher are called directly, so the platform's own implementation is never what is measured.
/// </summary>
internal static class FallbackTargets
{
    private static int s_sink;

    public static IEnumerable<TimingTarget> Targets()
    {
        yield return TimingTarget.FromBytes("Keccak", "sha3-224-secret-40B", 40, m => Sha3(Keccak.RateSha3_224, 28, m));
        yield return TimingTarget.FromBytes("Keccak", "sha3-256-secret-200B", 200, m => Sha3(Keccak.RateSha3_256, 32, m));
        yield return TimingTarget.FromBytes("Keccak", "sha3-512-secret-64B", 64, m => Sha3(Keccak.RateSha3_512, 64, m));
        yield return TimingTarget.FromBytes("Keccak", "shake128-secret-32B-out-300B", 32, m => Shake(Keccak.RateShake128, 300, m));
        yield return TimingTarget.FromBytes("Keccak", "shake256-secret-57B-out-114B", 57, m => Shake(Keccak.RateShake256, 114, m));

        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] aad = RandomNumberGenerator.GetBytes(13);
        byte[] fixedKey = RandomNumberGenerator.GetBytes(32);
        byte[] message = RandomNumberGenerator.GetBytes(1000);
        yield return new KeyTarget("encrypt-key-1000B", false, key => Seal(key, nonce, message, aad));
        yield return TimingTarget.FromBytes("ChaCha20-Poly1305", "encrypt-data-1000B", 1000, plain => Seal(fixedKey, nonce, plain, aad));
        yield return TimingTarget.FromBytes("ChaCha20-Poly1305", "control-encrypt-data-1000B", 1000, plain => Seal(fixedKey, nonce, plain, aad), control: true);
        yield return TimingTarget.FromBytes("ChaCha20-Poly1305", "pair-encrypt-data-1000B", 1000, plain => Seal(fixedKey, nonce, plain, aad), pair: true);
        // The same plaintext through Poly1305 alone, to tell the authenticator from the stream XOR and the block function.
        foreach (bool pair in new[] { false, true })
        {
            yield return TimingTarget.FromBytes("ChaCha20-Poly1305", (pair ? "pair-" : "") + "poly1305-data-1000B", 1000, plain => s_sink += ChaCha20Poly1305Managed.Poly1305Mac(fixedKey, plain)[0], pair: pair);
        }

        // The stream XOR alone (block function included) on the plaintext.
        foreach (bool pair in new[] { false, true })
        {
            yield return TimingTarget.FromBytes("ChaCha20-Poly1305", (pair ? "pair-" : "") + "xor-data-1000B", 1000, plain => XorOnly(fixedKey, nonce, plain), pair: pair);
        }

        // Harness controls on secret data of the same size, with nothing of ours in them: the platform's SHA-256, and a plain managed
        // byte loop. A flag here comes from the machine or the harness.
        foreach (bool pair in new[] { false, true })
        {
            string kind = pair ? "pair-" : "";
            yield return TimingTarget.FromBytes("HarnessData", kind + "sha256-1000B", 1000, plain => HashSink(plain), pair: pair);
            yield return TimingTarget.FromBytes("HarnessData", kind + "xor-loop-1000B", 1000, plain => XorSink(fixedKey, plain), pair: pair);
        }

        yield return new KeyTarget("encrypt-key-17B", false, key => Seal(key, nonce, message.AsSpan(0, 17), aad));
        yield return new KeyTarget("decrypt-wrong-tag-key-100B", false, key => Open(key, nonce, message.AsSpan(0, 100), aad));
        // A/A controls: both classes use fresh random keys.
        yield return new KeyTarget("control-encrypt-key-1000B", true, key => Seal(key, nonce, message, aad));
        yield return new KeyTarget("control-encrypt-key-17B", true, key => Seal(key, nonce, message.AsSpan(0, 17), aad));
        yield return new KeyTarget("control-decrypt-wrong-tag-key-100B", true, key => Open(key, nonce, message.AsSpan(0, 100), aad));
    }

    /// <summary>The key is the secret: one key buffer, refilled in the untimed hook by the same branch-free code in both classes.</summary>
    private sealed class KeyTarget(string operation, bool control, Action<byte[]> run) : TimingTarget
    {
        private readonly byte[] _fixedKey = RandomNumberGenerator.GetBytes(32);
        private readonly byte[] _key = new byte[32];
        private TimingClass[] _classes = [];

        public override string Primitive => "ChaCha20-Poly1305";

        public override string Operation => operation;

        public override void Prepare(ReadOnlySpan<TimingClass> classes) => _classes = classes.ToArray();

        public override void Before(int index) => FillKey(_key, _fixedKey, _classes[index], control);

        public override void Run(int index) => run(_key);
    }

    private static void XorOnly(byte[] key, byte[] nonce, byte[] plain)
    {
        Span<byte> ct = stackalloc byte[1000]; // fixed size
        ChaCha20Poly1305Managed.Xor(key, nonce, plain, ct);
        s_sink += ct[0];
    }

    private static void HashSink(byte[] plain)
    {
        Span<byte> digest = stackalloc byte[32]; // fixed size
        SHA256.HashData(plain, digest);
        s_sink += digest[0];
    }

    private static void XorSink(byte[] key, byte[] plain)
    {
        Span<byte> output = stackalloc byte[1000]; // fixed size
        for (int i = 0; i < output.Length; i++)
        {
            output[i] = (byte)(plain[i] ^ key[i & 31]);
        }

        s_sink += output[0];
    }

    private static void Sha3(int rate, int size, byte[] secret)
    {
        Span<byte> digest = stackalloc byte[64];
        Keccak.Hash(rate, Keccak.SuffixSha3, digest[..size], secret);
        s_sink += digest[0];
    }

    private static void Shake(int rate, int outLength, byte[] secret)
    {
        Span<byte> output = stackalloc byte[300];
        Keccak.Hash(rate, Keccak.SuffixShake, output[..outLength], secret);
        s_sink += output[0];
    }

    private static void Seal(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plain, ReadOnlySpan<byte> aad)
    {
        Span<byte> ct = stackalloc byte[1000];
        Span<byte> tag = stackalloc byte[16];
        ChaCha20Poly1305Managed.Encrypt(key, nonce, plain, ct[..plain.Length], tag, aad);
        s_sink += ct[0] + tag[0];
    }

    // A tag that does not match: the key decides the one-time Poly1305 key and the keystream, and the compare must not leak how far it agreed.
    private static void Open(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad)
    {
        Span<byte> plain = stackalloc byte[100];
        Span<byte> tag = stackalloc byte[16];
        s_sink += ChaCha20Poly1305Managed.TryDecrypt(key, nonce, ciphertext, tag, plain, aad) ? 1 : 0;
    }
}
