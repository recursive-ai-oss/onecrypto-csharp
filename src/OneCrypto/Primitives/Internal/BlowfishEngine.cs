using System.Runtime.CompilerServices;
using System.Buffers.Binary;

namespace RecursiveAI.OneCrypto.Primitives.Internal;

/// <summary>
/// Blowfish (Schneier, "Description of a New Variable-Length Key, 64-Bit Block Cipher", FSE 1993) with 32- to 448-bit keys.
/// </summary>
/// <remarks>
/// Side channels: the four S-boxes are indexed by data and are themselves derived from the key, so every lookup, in the rounds and
/// in the key schedule, reads the whole 256-entry box and selects by mask (<see cref="CtLookup.Word"/>). Key setup encrypts 521
/// blocks that way, which takes about a millisecond.
/// </remarks>
internal sealed class BlowfishEngine : BlockEngine
{
    private const int Rounds = 16;
    private const int PWords = Rounds + 2;
    private const int BoxWords = 256;

    // The P-array at [0, 18), then S-box i at [18 + 256 i, 18 + 256 (i + 1)).
    private readonly uint[] _state = GC.AllocateUninitializedArray<uint>(PWords + (4 * BoxWords), pinned: true);

    internal BlowfishEngine(ReadOnlySpan<byte> key)
    {
        if (key.Length is < 4 or > 56)
        {
            throw new ArgumentException("A Blowfish key is 4 to 56 bytes (32 to 448 bits).", nameof(key));
        }

        BlowfishTables.Initial.CopyTo(_state);
        int position = 0;
        for (int i = 0; i < PWords; i++)
        {
            // The key bytes are used cyclically, four at a time, big-endian (the paper's key expansion).
            uint word = 0;
            for (int j = 0; j < 4; j++)
            {
                word = (word << 8) | key[position];
                position = (position + 1) % key.Length;
            }

            _state[i] ^= word;
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

    internal override int BlockSize => 8;

    [MethodImpl(MethodImplOptions.NoInlining)]
    private uint F(uint x)
    {
        ReadOnlySpan<uint> s = _state;
        uint a = CtLookup.Word(s.Slice(PWords, BoxWords), x >> 24);
        uint b = CtLookup.Word(s.Slice(PWords + BoxWords, BoxWords), (x >> 16) & 0xFF);
        uint c = CtLookup.Word(s.Slice(PWords + (2 * BoxWords), BoxWords), (x >> 8) & 0xFF);
        uint d = CtLookup.Word(s.Slice(PWords + (3 * BoxWords), BoxWords), x & 0xFF);
        return ((a + b) ^ c) + d;
    }

    private void Encrypt(ref uint l, ref uint r)
    {
        uint x = l;
        uint y = r;
        for (int i = 0; i < Rounds; i++)
        {
            x ^= _state[i];
            y ^= F(x);
            (x, y) = (y, x);
        }

        (x, y) = (y, x);
        y ^= _state[Rounds];
        x ^= _state[Rounds + 1];
        l = x;
        r = y;
    }

    private void Decrypt(ref uint l, ref uint r)
    {
        uint x = l;
        uint y = r;
        for (int i = Rounds + 1; i > 1; i--)
        {
            x ^= _state[i];
            y ^= F(x);
            (x, y) = (y, x);
        }

        (x, y) = (y, x);
        y ^= _state[1];
        x ^= _state[0];
        l = x;
        r = y;
    }

    internal override void EncryptBlock(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        uint l = BinaryPrimitives.ReadUInt32BigEndian(source);
        uint r = BinaryPrimitives.ReadUInt32BigEndian(source[4..]);
        Encrypt(ref l, ref r);
        BinaryPrimitives.WriteUInt32BigEndian(destination, l);
        BinaryPrimitives.WriteUInt32BigEndian(destination[4..], r);
    }

    internal override void DecryptBlock(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        uint l = BinaryPrimitives.ReadUInt32BigEndian(source);
        uint r = BinaryPrimitives.ReadUInt32BigEndian(source[4..]);
        Decrypt(ref l, ref r);
        BinaryPrimitives.WriteUInt32BigEndian(destination, l);
        BinaryPrimitives.WriteUInt32BigEndian(destination[4..], r);
    }

    public override void Dispose() => WordWipe.Clear(_state);
}
