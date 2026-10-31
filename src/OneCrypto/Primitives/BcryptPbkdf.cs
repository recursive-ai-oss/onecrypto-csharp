using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Primitives.Internal;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// bcrypt-pbkdf: the password-based key derivation OpenSSH uses for passphrase-protected <c>openssh-key-v1</c> private keys
/// (the <c>bcrypt</c> KDF of the key format). It hashes the password and salt with SHA-512 and runs bcrypt's expensive
/// Blowfish key schedule on the digests, mixing the outputs of all rounds.
/// </summary>
/// <remarks>
/// Side channels: Blowfish reads its S-boxes at data-dependent indices, so the cache lines touched depend on the password.
/// Making every lookup scan the whole table would multiply the cost by 256; the function exists to unlock local key files, where
/// an attacker would need to share the CPU cache. Nothing else branches on the password. Cost is bounded by
/// <see cref="KdfLimits.MaxBcryptRounds"/>.
/// </remarks>
public static class BcryptPbkdf
{
    private const int HashBytes = 32;

    // The bcrypt magic text is encrypted in ECB mode (Provos and Mazières, 1999).
    private static ReadOnlySpan<byte> MagicText => "OxychromaticBlowfishSwatDynamite"u8;

    /// <summary>Derives <paramref name="destination"/>.Length bytes (1 to 1024).</summary>
    /// <param name="password">The password.</param>
    /// <param name="salt">The salt (OpenSSH stores a 16-byte one in the key file); not empty.</param>
    /// <param name="rounds">The number of rounds (OpenSSH's <c>-a</c>); at least 1.</param>
    /// <param name="destination">Receives the key material. OpenSSH asks for the cipher key followed by the IV.</param>
    /// <param name="limits">Cost bounds; <see cref="KdfLimits.Default"/> when <see langword="null"/>.</param>
    /// <exception cref="ArgumentException">A parameter is out of range.</exception>
    /// <exception cref="KdfLimitExceededException">The rounds exceed <paramref name="limits"/>.</exception>
    public static void DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int rounds, Span<byte> destination, KdfLimits? limits = null)
    {
        limits ??= KdfLimits.Default;
        ArgumentOutOfRangeException.ThrowIfLessThan(rounds, 1);
        ArgumentOutOfRangeException.ThrowIfZero(destination.Length);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(destination.Length, 1024);
        if (salt.IsEmpty)
        {
            throw new ArgumentException("The bcrypt-pbkdf salt must not be empty.", nameof(salt));
        }

        KdfLimits.Require("bcrypt-pbkdf", "rounds", rounds, limits.MaxBcryptRounds);

        Span<byte> passHash = stackalloc byte[64]; // fixed 64-byte buffers: SHA-512 outputs
        Span<byte> saltHash = stackalloc byte[64];
        Span<byte> output = stackalloc byte[HashBytes];
        Span<byte> block = stackalloc byte[HashBytes];
        byte[] countedSalt = new byte[salt.Length + 4];
        salt.CopyTo(countedSalt);
        SHA512.HashData(password, passHash);

        // The output bytes are dealt out round-robin: byte i of block `count` goes to position i * stride + count - 1.
        int length = destination.Length;
        int stride = (length + HashBytes - 1) / HashBytes;
        int perBlock = (length + stride - 1) / stride;
        using var blowfish = new BlowfishCore();
        for (int count = 1; count <= stride; count++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(countedSalt.AsSpan(salt.Length), (uint)count);
            SHA512.HashData(countedSalt, saltHash);
            Hash(blowfish, passHash, saltHash, block);
            block.CopyTo(output);
            for (int round = 1; round < rounds; round++)
            {
                SHA512.HashData(block, saltHash);
                Hash(blowfish, passHash, saltHash, block);
                for (int i = 0; i < HashBytes; i++)
                {
                    output[i] ^= block[i];
                }
            }

            for (int i = 0; i < perBlock; i++)
            {
                int target = (i * stride) + (count - 1);
                if (target >= length)
                {
                    break;
                }

                destination[target] = output[i];
            }
        }

        CryptographicOperations.ZeroMemory(passHash);
        CryptographicOperations.ZeroMemory(saltHash);
        CryptographicOperations.ZeroMemory(output);
        CryptographicOperations.ZeroMemory(block);
    }

    /// <summary>Derives a key of <paramref name="length"/> bytes; see the span overload for the parameters.</summary>
    public static byte[] DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int rounds, int length, KdfLimits? limits = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(length, 1);
        byte[] key = new byte[length];
        DeriveKey(password, salt, rounds, key, limits);
        return key;
    }

    // bcrypt's core, fed with SHA-512 digests of the password and salt instead of the raw values.
    private static void Hash(BlowfishCore blowfish, ReadOnlySpan<byte> passHash, ReadOnlySpan<byte> saltHash, Span<byte> output)
    {
        blowfish.Reset();
        blowfish.ExpandKey(saltHash, passHash);
        for (int i = 0; i < 64; i++)
        {
            blowfish.ExpandKey(saltHash);
            blowfish.ExpandKey(passHash);
        }

        uint[] words = new uint[8];
        ReadOnlySpan<byte> magic = MagicText;
        for (int i = 0; i < 8; i++)
        {
            words[i] = BinaryPrimitives.ReadUInt32BigEndian(magic[(4 * i)..]);
        }

        for (int i = 0; i < 64; i++)
        {
            for (int pair = 0; pair < 8; pair += 2)
            {
                blowfish.Encrypt(ref words[pair], ref words[pair + 1]);
            }
        }

        // Unlike bcrypt itself, bcrypt-pbkdf emits the words little-endian.
        for (int i = 0; i < 8; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(output[(4 * i)..], words[i]);
        }

        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(words.AsSpan()));
    }
}
