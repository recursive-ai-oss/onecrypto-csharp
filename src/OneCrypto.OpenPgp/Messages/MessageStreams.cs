using System.Buffers.Binary;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>
/// Writes one new-format packet whose length is not known in advance, as partial body lengths followed by a final definite length (RFC 9580 §4.2.1.4).
/// Memory is one buffer, whatever the size of the body. <see cref="Complete"/> writes the last chunk; nothing is written to the output before the
/// first buffer fills or the packet ends.
/// </summary>
internal sealed class PacketBodyWriter : Stream
{
    // 2^13 octets per partial chunk: at least the 512 octets the first partial chunk needs (RFC 9580 §4.2.1.4) and small enough to keep memory low.
    private const int Partial = 8192;
    private const byte PartialOctet = 224 + 13;

    private readonly Stream _out;
    private readonly byte _tag;
    private readonly byte[] _buf = new byte[Partial];
    private int _n;
    private bool _headerDone;
    private bool _completed;

    internal PacketBodyWriter(Stream output, PacketTag tag)
    {
        _out = output;
        _tag = (byte)(0xC0 | (byte)tag);
    }

    public override bool CanRead => false;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> data)
    {
        while (!data.IsEmpty)
        {
            if (_n == Partial)
            {
                // More data follows a full buffer, so it is not the last chunk.
                if (!_headerDone)
                {
                    _out.WriteByte(_tag);
                    _headerDone = true;
                }

                _out.WriteByte(PartialOctet);
                _out.Write(_buf, 0, Partial);
                _n = 0;
            }

            int take = Math.Min(data.Length, Partial - _n);
            data[..take].CopyTo(_buf.AsSpan(_n));
            _n += take;
            data = data[take..];
        }
    }

    /// <summary>Writes the final chunk and its definite length.</summary>
    internal void Complete()
    {
        if (_completed)
        {
            return;
        }

        _completed = true;
        if (!_headerDone)
        {
            _out.WriteByte(_tag);
        }

        if (_n < 192)
        {
            _out.WriteByte((byte)_n);
        }
        else if (_n < 8384)
        {
            int v = _n - 192;
            _out.WriteByte((byte)(192 + (v >> 8)));
            _out.WriteByte((byte)v);
        }
        else
        {
            _out.WriteByte(0xFF);
            Span<byte> l = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(l, (uint)_n);
            _out.Write(l);
        }

        _out.Write(_buf, 0, _n);
    }

    public override void Flush()
    {
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            Complete();
        }

        base.Dispose(disposing);
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();
}

/// <summary>The chunked AEAD framing shared by SEIPD v2 (RFC 9580 §5.13.2) and LibrePGP's OCB Encrypted Data.</summary>
internal sealed class AeadFraming
{
    internal AeadFraming(AeadAlgorithm aead, int chunkOctet, byte[] key, byte[] ivOrPrefix, byte[] adHead, bool ocbed)
    {
        Aead = aead;
        ChunkSize = 1 << (chunkOctet + 6);
        Key = key;
        IvOrPrefix = ivOrPrefix;
        AdHead = adHead;
        IsOcbed = ocbed;
    }

    internal AeadAlgorithm Aead { get; }

    internal int ChunkSize { get; }

    internal byte[] Key { get; }

    internal byte[] IvOrPrefix { get; }

    internal byte[] AdHead { get; }

    internal bool IsOcbed { get; }

    internal byte[] Nonce(ulong index)
    {
        int n = PgpAlgorithms.NonceSize(Aead);
        byte[] nonce = new byte[n];
        if (IsOcbed)
        {
            // LibrePGP §5.16.2: the starting IV exclusive-ored with the chunk index, as a big-endian value in the last eight octets.
            IvOrPrefix.CopyTo(nonce, 0);
            for (int i = 0; i < 8; i++)
            {
                nonce[n - 1 - i] ^= (byte)(index >> (8 * i));
            }
        }
        else
        {
            // RFC 9580 §5.13.2: N-64 bits of derived IV, then the 64-bit big-endian chunk index.
            IvOrPrefix.CopyTo(nonce, 0);
            BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(n - 8), index);
        }

        return nonce;
    }

    internal byte[] ChunkAd(ulong index)
    {
        if (!IsOcbed)
        {
            return AdHead;
        }

        return [.. AdHead, .. PgpAlgorithms.BigEndian(index)];
    }

    internal byte[] FinalAd(ulong index, ulong total) => [.. ChunkAd(index), .. PgpAlgorithms.BigEndian(total)];

    /// <summary>Derives the SEIPD v2 framing: HKDF-SHA256 gives the message key and the IV prefix (RFC 9580 §5.13.2).</summary>
    internal static AeadFraming ForSeipd2(SymmetricAlgorithm cipher, AeadAlgorithm aead, byte chunkOctet, byte[] sessionKey, ReadOnlySpan<byte> salt)
    {
        int keySize = PgpAlgorithms.KeySize(cipher);
        int ivSize = PgpAlgorithms.NonceSize(aead) - 8;
        byte[] info = [0xD2, 2, (byte)cipher, (byte)aead, chunkOctet];
        byte[] okm = HKDF.DeriveKey(HashAlgorithmName.SHA256, sessionKey, keySize + ivSize, salt.ToArray(), info);
        byte[] key = okm.AsSpan(0, keySize).ToArray();
        byte[] iv = okm.AsSpan(keySize, ivSize).ToArray();
        CryptographicOperations.ZeroMemory(okm);
        return new AeadFraming(aead, chunkOctet, key, iv, info, false);
    }
}

/// <summary>Encrypts a SEIPD v2 body chunk by chunk (RFC 9580 §5.13.2) into the underlying stream.</summary>
internal sealed class AeadChunkWriter : Stream
{
    private readonly Stream _out;
    private readonly AeadFraming _f;
    private readonly PgpAlgorithms.Aead _aead;
    private readonly byte[] _chunk;
    private readonly byte[] _ct;
    private int _n;
    private ulong _index;
    private ulong _total;
    private bool _completed;

    internal AeadChunkWriter(Stream output, AeadFraming framing)
    {
        _out = output;
        _f = framing;
        _aead = new PgpAlgorithms.Aead(framing.Aead, framing.Key);
        _chunk = new byte[framing.ChunkSize];
        _ct = new byte[framing.ChunkSize];
    }

    public override bool CanRead => false;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> data)
    {
        while (!data.IsEmpty)
        {
            int take = Math.Min(data.Length, _chunk.Length - _n);
            data[..take].CopyTo(_chunk.AsSpan(_n));
            _n += take;
            data = data[take..];
            if (_n == _chunk.Length)
            {
                Emit();
            }
        }
    }

    private void Emit()
    {
        Span<byte> tag = new byte[16];
        _aead.Encrypt(_f.Nonce(_index), _chunk.AsSpan(0, _n), _ct.AsSpan(0, _n), tag, _f.ChunkAd(_index));
        _out.Write(_ct, 0, _n);
        _out.Write(tag);
        _total += (ulong)_n;
        _index++;
        _n = 0;
    }

    /// <summary>Writes the last partial chunk and the final authentication tag over the empty string.</summary>
    internal void Complete()
    {
        if (_completed)
        {
            return;
        }

        _completed = true;
        if (_n > 0)
        {
            Emit();
        }

        Span<byte> tag = new byte[16];
        _aead.Encrypt(_f.Nonce(_index), default, default, tag, _f.FinalAd(_index, _total));
        _out.Write(tag);
        CryptographicOperations.ZeroMemory(_chunk);
    }

    public override void Flush()
    {
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            Complete();
            _aead.Dispose();
        }

        base.Dispose(disposing);
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();
}

/// <summary>Encrypts a SEIPD v1 body: random prefix, CFB, trailing MDC (RFC 9580 §5.13.1).</summary>
internal sealed class CfbMdcWriter : Stream
{
    private readonly Stream _out;
    private readonly byte[] _key;
    private readonly byte[] _iv = new byte[16];
    private readonly IncrementalHash _sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
    private readonly byte[] _buf = new byte[16 * 1024];
    private int _n;
    private bool _completed;

    internal CfbMdcWriter(Stream output, byte[] key)
    {
        _out = output;
        _key = key;
        byte[] prefix = RandomNumberGenerator.GetBytes(16);
        Write(prefix);
        Write([prefix[14], prefix[15]]);
    }

    public override bool CanRead => false;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> data)
    {
        _sha1.AppendData(data);
        Buffer(data);
    }

    private void Buffer(ReadOnlySpan<byte> data)
    {
        while (!data.IsEmpty)
        {
            int take = Math.Min(data.Length, _buf.Length - _n);
            data[..take].CopyTo(_buf.AsSpan(_n));
            _n += take;
            data = data[take..];
            if (_n == _buf.Length)
            {
                Flush16();
            }
        }
    }

    private void Flush16()
    {
        PgpAlgorithms.CfbEncrypt(_key, _iv, _buf.AsSpan(0, _n));
        _out.Write(_buf, 0, _n);
        _n = 0;
    }

    /// <summary>Appends the MDC packet (RFC 9580 §5.14: 0xD3 0x14 and the SHA-1 of everything before the digest) and flushes.</summary>
    internal void Complete()
    {
        if (_completed)
        {
            return;
        }

        _completed = true;
        _sha1.AppendData([0xD3, 0x14]);
        byte[] digest = _sha1.GetHashAndReset();
        Buffer([0xD3, 0x14]);
        Buffer(digest);
        if (_n > 0)
        {
            Flush16();
        }
    }

    public override void Flush()
    {
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            Complete();
            _sha1.Dispose();
        }

        base.Dispose(disposing);
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();
}

/// <summary>
/// Decrypts chunked AEAD data and releases a chunk only after it authenticates. A bad tag, a truncated stream or a wrong final tag throws
/// <see cref="PgpException"/> (<see cref="PgpFailure.CannotDecrypt"/>) from the read that reaches it: the caller has by then received every chunk
/// that did authenticate, and nothing after the failure.
/// </summary>
internal sealed class AeadChunkReader : Stream
{
    private readonly Stream _in;
    private readonly AeadFraming _f;
    private readonly PgpAlgorithms.Aead _aead;
    private readonly byte[] _carry;
    private int _carryLen;
    private readonly byte[] _plain;
    private int _plainPos;
    private int _plainLen;
    private ulong _index;
    private ulong _total;
    private bool _done;

    internal AeadChunkReader(Stream cipherBody, AeadFraming framing)
    {
        _in = cipherBody;
        _f = framing;
        _aead = new PgpAlgorithms.Aead(framing.Aead, framing.Key);
        _carry = new byte[framing.ChunkSize + 16 + 16];
        _plain = new byte[framing.ChunkSize];
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> destination)
    {
        if (destination.IsEmpty)
        {
            return 0;
        }

        while (_plainPos == _plainLen)
        {
            if (_done)
            {
                return 0;
            }

            NextChunk();
        }

        int n = Math.Min(destination.Length, _plainLen - _plainPos);
        _plain.AsSpan(_plainPos, n).CopyTo(destination);
        _plainPos += n;
        return n;
    }

    private static PgpException Fail() => new(PgpFailure.CannotDecrypt, "The encrypted data could not be decrypted.");

    private void NextChunk()
    {
        // Fill the look-ahead: a full chunk with its tag, plus the 16 octets that might be the final tag.
        int want = _carry.Length - _carryLen;
        while (want > 0)
        {
            int got = _in.Read(_carry, _carryLen, want);
            if (got == 0)
            {
                break;
            }

            _carryLen += got;
            want -= got;
        }

        int chunkWire = _f.ChunkSize + 16;
        if (_carryLen == _carry.Length)
        {
            // More data follows this chunk, so it is a normal chunk.
            Open(chunkWire);
            Buffer.BlockCopy(_carry, chunkWire, _carry, 0, _carryLen - chunkWire);
            _carryLen -= chunkWire;
            return;
        }

        // End of the packet: the last 16 octets are the final tag; anything before them is a last, shorter chunk.
        if (_carryLen < 16)
        {
            throw Fail();
        }

        int last = _carryLen - 16;
        if (last > 0)
        {
            if (last < 16)
            {
                throw Fail();
            }

            Open(last);
        }
        else
        {
            _plainPos = _plainLen = 0;
        }

        byte[] finalTag = _carry.AsSpan(last, 16).ToArray();
        bool ok = _aead.TryDecrypt(_f.Nonce(_index), default, finalTag, default, _f.FinalAd(_index, _total));
        _done = true;
        _carryLen = 0;
        if (!ok)
        {
            // The last chunk already authenticated but the length check failed: it is not released.
            _plainPos = _plainLen = 0;
            throw Fail();
        }
    }

    private void Open(int wireLength)
    {
        int ctLen = wireLength - 16;
        bool ok = _aead.TryDecrypt(_f.Nonce(_index), _carry.AsSpan(0, ctLen), _carry.AsSpan(ctLen, 16), _plain.AsSpan(0, ctLen), _f.ChunkAd(_index));
        if (!ok)
        {
            _plainPos = _plainLen = 0;
            _done = true;
            throw Fail();
        }

        _plainPos = 0;
        _plainLen = ctLen;
        _total += (ulong)ctLen;
        _index++;
        if (ctLen < _f.ChunkSize)
        {
            // A short chunk can only be the last one; the final tag is checked by the caller's next step.
        }
    }

    public override void Flush()
    {
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _aead.Dispose();
            CryptographicOperations.ZeroMemory(_plain);
        }

        base.Dispose(disposing);
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>
/// A seekable scratch stream that holds up to a threshold in memory and spills to a temporary file beyond it. Used where plaintext must not be
/// released before an integrity check over the whole body (SEIPD v1's MDC).
/// </summary>
internal sealed class SpoolStream : Stream
{
    private const int Threshold = 4 << 20;
    private Stream _s = new MemoryStream();
    private string? _path;

    public override bool CanRead => true;

    public override bool CanSeek => true;

    public override bool CanWrite => true;

    public override long Length => _s.Length;

    public override long Position
    {
        get => _s.Position;
        set => _s.Position = value;
    }

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        if (_path is null && _s.Length + buffer.Length > Threshold)
        {
            _path = Path.Combine(Path.GetTempPath(), "onecrypto-" + Guid.NewGuid().ToString("N") + ".tmp");
            var file = new FileStream(_path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 1 << 16, FileOptions.DeleteOnClose);
            _s.Position = 0;
            _s.CopyTo(file);
            _s.Dispose();
            _s = file;
        }

        _s.Write(buffer);
    }

    public override int Read(byte[] buffer, int offset, int count) => _s.Read(buffer, offset, count);

    public override int Read(Span<byte> buffer) => _s.Read(buffer);

    public override long Seek(long offset, SeekOrigin origin) => _s.Seek(offset, origin);

    public override void SetLength(long value) => _s.SetLength(value);

    public override void Flush() => _s.Flush();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _s.Dispose();
        }

        base.Dispose(disposing);
    }
}

/// <summary>
/// Decrypts the body of a Symmetrically Encrypted Data packet (tag 9): CFB with a zero IV over a random prefix of one block and two repeated
/// octets, after which the feedback register is reloaded from the ciphertext (the "resync" of RFC 4880 §13.9). There is no integrity
/// protection, so the reader only builds this when the caller opted in.
/// </summary>
internal sealed class SedDecryptStream : Stream
{
    private readonly Stream _body;
    private readonly SymmetricAlgorithm _cipher;
    private readonly byte[] _key;
    private readonly int _block;
    private readonly byte[] _iv = new byte[16];
    private readonly byte[] _carry = new byte[16];
    private int _carryLen;
    private readonly byte[] _ready = new byte[64 * 1024];
    private int _readyPos;
    private int _readyLen;
    private bool _eof;

    private SedDecryptStream(Stream body, SymmetricAlgorithm cipher, byte[] key)
    {
        _body = body;
        _cipher = cipher;
        _key = key;
        _block = PgpAlgorithms.BlockSize(cipher);
    }

    /// <summary>
    /// Checks the prefix in <paramref name="head"/> (the first octets of the body, at least a block and two) with <paramref name="cipher"/> and
    /// <paramref name="key"/>; null when the two check octets do not repeat. <paramref name="rest"/> continues after the prefix block.
    /// </summary>
    internal static SedDecryptStream? TryOpen(byte[] head, Stream rest, SymmetricAlgorithm cipher, byte[] key)
    {
        int bs = PgpAlgorithms.BlockSize(cipher);
        if (head.Length < bs + 2)
        {
            return null;
        }

        byte[] plain = head.AsSpan(0, bs + 2).ToArray();
        PgpAlgorithms.CfbDecrypt(cipher, key, new byte[16], plain);
        if (plain[bs - 2] != plain[bs] || plain[bs - 1] != plain[bs + 1])
        {
            return null;
        }

        var s = new SedDecryptStream(new PrefixStream(head.AsSpan(bs + 2).ToArray(), rest), cipher, (byte[])key.Clone());
        // The register restarts from the ciphertext octets 2..bs+2 (RFC 4880 §13.9).
        head.AsSpan(2, bs).CopyTo(s._iv);
        return s;
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        if (buffer.IsEmpty)
        {
            return 0;
        }

        while (_readyPos == _readyLen)
        {
            if (_eof)
            {
                return 0;
            }

            Fill();
        }

        int take = Math.Min(buffer.Length, _readyLen - _readyPos);
        _ready.AsSpan(_readyPos, take).CopyTo(buffer);
        _readyPos += take;
        return take;
    }

    private void Fill()
    {
        _carry.AsSpan(0, _carryLen).CopyTo(_ready);
        int n = _body.Read(_ready, _carryLen, _ready.Length - _carryLen);
        int total = _carryLen + n;
        if (n == 0)
        {
            _eof = true;
            PgpAlgorithms.CfbDecrypt(_cipher, _key, _iv, _ready.AsSpan(0, total));
            _readyPos = 0;
            _readyLen = total;
            _carryLen = 0;
            return;
        }

        int whole = total - (total % _block);
        PgpAlgorithms.CfbDecrypt(_cipher, _key, _iv, _ready.AsSpan(0, whole));
        _carryLen = total - whole;
        _ready.AsSpan(whole, _carryLen).CopyTo(_carry);
        _readyPos = 0;
        _readyLen = whole;
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            CryptographicOperations.ZeroMemory(_key);
            _body.Dispose();
        }

        base.Dispose(disposing);
    }
}
