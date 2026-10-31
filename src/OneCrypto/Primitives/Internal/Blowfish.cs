using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Primitives.Internal;

/// <summary>
/// The Blowfish block cipher's state and key schedule (Schneier, 1993), with the salted "expensive" key schedule that
/// bcrypt and bcrypt-pbkdf are built on (Provos and Mazières, "A Future-Adaptable Password Scheme", 1999).
/// </summary>
/// <remarks>
/// <para>Side channels: Blowfish indexes its S-boxes with data-dependent bytes. Scanning every table entry with masks would make
/// each round 256 times as costly, which is not affordable for a cipher whose only users here are local key files and legacy
/// messages, so lookups are direct. A co-resident attacker that can observe cache lines could learn about the key schedule.
/// This is documented where the cipher is exposed.</para>
/// <para>Words are big-endian when read from bytes, as in the paper.</para>
/// </remarks>
internal sealed class BlowfishCore : IDisposable
{
    private const int Rounds = 16;
    private const int PWords = Rounds + 2;
    private const int SBoxWords = 256;

    // P-array at [0, 18), then S-box i at [18 + 256 * i, 18 + 256 * (i + 1)).
    private readonly uint[] _state = GC.AllocateUninitializedArray<uint>(PWords + (4 * SBoxWords), pinned: true);

    /// <summary>Creates a state holding the initial (pi) values, before any key.</summary>
    public BlowfishCore() => Reset();

    /// <summary>Restores the initial values.</summary>
    public void Reset() => BlowfishTables.Initial.CopyTo(_state);

    /// <summary>
    /// Blowfish key setup (1 to 72 bytes are meaningful; longer keys are cycled as the paper's key schedule does) starting from
    /// the initial values: the key is XORed into the P-array, then P and the S-boxes are replaced by successive encryptions of
    /// an all-zero block.
    /// </summary>
    public void SetKey(ReadOnlySpan<byte> key)
    {
        Reset();
        ExpandKey(key);
    }

    /// <summary>
    /// bcrypt's expensive key schedule, step "ExpandKey(state, salt, key)": like the plain key schedule, but each encrypted
    /// block is first XORed with the next 8 bytes of the cycled salt.
    /// </summary>
    public void ExpandKey(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> key)
    {
        int keyPosition = 0;
        for (int i = 0; i < PWords; i++)
        {
            _state[i] ^= NextWord(key, ref keyPosition);
        }

        uint l = 0;
        uint r = 0;
        int saltPosition = 0;
        for (int i = 0; i < _state.Length; i += 2)
        {
            l ^= NextWord(salt, ref saltPosition);
            r ^= NextWord(salt, ref saltPosition);
            Encrypt(ref l, ref r);
            _state[i] = l;
            _state[i + 1] = r;
        }
    }

    /// <summary>The unsalted key schedule step "ExpandKey(state, 0, key)"; with the initial values it is the standard Blowfish key setup.</summary>
    public void ExpandKey(ReadOnlySpan<byte> key)
    {
        int keyPosition = 0;
        for (int i = 0; i < PWords; i++)
        {
            _state[i] ^= NextWord(key, ref keyPosition);
        }

        uint l = 0;
        uint r = 0;
        for (int i = 0; i < _state.Length; i += 2)
        {
            Encrypt(ref l, ref r);
            _state[i] = l;
            _state[i + 1] = r;
        }
    }

    /// <summary>Encrypts one 64-bit block held as two big-endian words.</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    public void Encrypt(ref uint left, ref uint right)
    {
        uint[] s = _state;
        uint l = left ^ s[0];
        uint r = right;
        for (int i = 1; i <= Rounds; i += 2)
        {
            r ^= F(s, l) ^ s[i];
            l ^= F(s, r) ^ s[i + 1];
        }

        left = r ^ s[Rounds + 1];
        right = l;
    }

    /// <summary>Decrypts one 64-bit block held as two big-endian words.</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    public void Decrypt(ref uint left, ref uint right)
    {
        uint[] s = _state;
        uint l = left ^ s[Rounds + 1];
        uint r = right;
        for (int i = Rounds; i >= 2; i -= 2)
        {
            r ^= F(s, l) ^ s[i];
            l ^= F(s, r) ^ s[i - 1];
        }

        left = r ^ s[0];
        right = l;
    }

    /// <inheritdoc />
    public void Dispose() => CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(_state.AsSpan()));

    // The paper's F: ((S1[a] + S2[b]) xor S3[c]) + S4[d] with a the top byte.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint F(uint[] s, uint x) =>
        ((s[PWords + (int)(x >> 24)] + s[PWords + SBoxWords + (int)((x >> 16) & 0xFF)])
            ^ s[PWords + (2 * SBoxWords) + (int)((x >> 8) & 0xFF)])
        + s[PWords + (3 * SBoxWords) + (int)(x & 0xFF)];

    // Four bytes of the data, big-endian, wrapping around to its start.
    private static uint NextWord(ReadOnlySpan<byte> data, ref int position)
    {
        uint word = 0;
        for (int i = 0; i < 4; i++)
        {
            word = (word << 8) | data[position];
            position = position + 1 == data.Length ? 0 : position + 1;
        }

        return word;
    }
}
