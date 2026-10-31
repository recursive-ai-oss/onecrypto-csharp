using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Internal;

/// <summary>
/// A byte buffer for key material. It is allocated on the pinned object heap so the garbage collector never moves it (no stray
/// copies are left behind by compaction), and it is zeroed when disposed. A garbage-collected runtime cannot guarantee that no other
/// copy of a secret exists; this narrows the window, it does not close it.
/// </summary>
internal sealed class PinnedSecret : IDisposable
{
    private byte[]? _buffer;

    /// <summary>Creates a zero-filled secret of <paramref name="length"/> bytes.</summary>
    public PinnedSecret(int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        byte[] buffer = GC.AllocateUninitializedArray<byte>(length, pinned: true);
        buffer.AsSpan().Clear();
        _buffer = buffer;
    }

    /// <summary>Creates a secret holding a copy of <paramref name="value"/>. The caller still owns, and should zero, its own copy.</summary>
    public PinnedSecret(ReadOnlySpan<byte> value)
        : this(value.Length)
    {
        value.CopyTo(_buffer);
    }

    /// <summary>The number of bytes held.</summary>
    /// <exception cref="ObjectDisposedException">The secret has been disposed.</exception>
    public int Length => Buffer.Length;

    /// <summary>The secret bytes, writable. Do not keep the span past Dispose.</summary>
    /// <exception cref="ObjectDisposedException">The secret has been disposed.</exception>
    public Span<byte> Span => Buffer;

    /// <summary>The secret bytes, read-only.</summary>
    /// <exception cref="ObjectDisposedException">The secret has been disposed.</exception>
    public ReadOnlySpan<byte> ReadOnlySpan => Buffer;

    private byte[] Buffer => _buffer ?? throw new ObjectDisposedException(nameof(PinnedSecret));

    /// <summary>Zeroes the buffer and releases it. Safe to call more than once.</summary>
    public void Dispose()
    {
        byte[]? buffer = _buffer;
        _buffer = null;
        if (buffer is not null)
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }
}
