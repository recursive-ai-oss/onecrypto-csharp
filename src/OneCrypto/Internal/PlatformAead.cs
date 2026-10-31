using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Internal;

/// <summary>ChaCha20-Poly1305 (RFC 8439) through the platform dispatch: the platform's where it has one, the managed one elsewhere.</summary>
internal static class PlatformAead
{
    /// <summary>Encrypts and authenticates.</summary>
    /// <param name="key">32 bytes.</param>
    /// <param name="nonce">12 bytes; never reuse one under a key.</param>
    /// <param name="plaintext">The message.</param>
    /// <param name="ciphertext">Receives the same number of bytes.</param>
    /// <param name="tag">Receives the 16-byte tag.</param>
    /// <param name="aad">Associated data.</param>
    public static void ChaCha20Poly1305Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> aad)
    {
        if (Platform.ChaCha20Poly1305Support == Provider.Bcl)
        {
            using var aead = new ChaCha20Poly1305(key);
            aead.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            return;
        }

        Primitives.Fallback.ChaCha20Poly1305Managed.Encrypt(key, nonce, plaintext, ciphertext, tag, aad);
    }

    /// <summary>Verifies the tag and decrypts; nothing is released when the tag is wrong.</summary>
    /// <returns>False when authentication fails; <paramref name="plaintext"/> is then zeroed.</returns>
    public static bool ChaCha20Poly1305TryDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        if (Platform.ChaCha20Poly1305Support == Provider.Bcl)
        {
            using var aead = new ChaCha20Poly1305(key);
            try
            {
                aead.Decrypt(nonce, ciphertext, tag, plaintext, aad);
                return true;
            }
            catch (AuthenticationTagMismatchException)
            {
                // The platform reports a wrong tag by exception; this is the failure path, not the hot one.
                plaintext.Clear();
                return false;
            }
        }

        return Primitives.Fallback.ChaCha20Poly1305Managed.TryDecrypt(key, nonce, ciphertext, tag, plaintext, aad);
    }
}
