using RecursiveAI.OneCrypto.Pkcs;

namespace RecursiveAI.OneCrypto;

/// <summary>
/// The root of the happy path for files: <see cref="Load(string, Func{string, string?}?, CancellationToken)"/> takes a key or
/// certificate file in any common format and returns what it holds, typed. For example, loading a private key and signing with it:
/// <code>using LoadedItems f = Crypto.Load("key.pem", _ =&gt; "secret"); byte[] sig = f.PrivateKeys[0].Signing!.Sign(data, f.PrivateKeys[0].Signing!.DefaultSpec);</code>
/// </summary>
/// <remarks>
/// <para><b>Formats.</b> DER and BER; PEM with any number of blocks and text around them; X.509 certificates, CRLs, certification
/// requests and OCSP responses; <c>SubjectPublicKeyInfo</c> and PKCS#1 public keys; PKCS#8 private keys (plain and encrypted), PKCS#1
/// and SEC 1 keys and OpenSSL's legacy <c>DEK-Info</c> encryption; PKCS#12; PKCS#7 certificate bags (<c>.p7b</c>); OpenSSH private
/// keys, public keys, certificates, <c>authorized_keys</c> lines and RFC 4716 files. The exact decision table is in the load notes.
/// Not read here: OpenPGP keys (armored blocks are reported as unrecognised, with a reason), age, minisign and Sigstore files, and
/// attribute certificates.</para>
/// <para><b>Passwords.</b> The callback receives a short description of the encrypted item and returns its password, or null when
/// there is none. It is called at most once per encrypted item, and not at all when a password that already opened an earlier item
/// in the same file opens this one. A PKCS#12 file that no supplied password opens is tried with the empty password. A wrong password
/// is <see cref="CryptoLoadError.WrongPasswordOrCorrupt"/> and nothing from the file is returned. Password strings stay in managed
/// memory; the library cannot erase them.</para>
/// <para><b>Limits.</b> Input over 64 MiB, KDF costs above the container limits and ASN.1 nesting deeper than 24 are refused with
/// <see cref="CryptoLoadError.LimitExceeded"/> before any expensive work. Time is not involved: nothing here validates a certificate.</para>
/// <para><b>Errors.</b> Bad input throws only <see cref="CryptoLoadException"/>; <c>TryLoad</c> returns it. I/O errors from reading a
/// stream or path propagate unchanged.</para>
/// </remarks>
public static class Crypto
{
    /// <summary>Loads what <paramref name="data"/> holds.</summary>
    /// <param name="data">The file contents.</param>
    /// <param name="password">Called to get the password of an encrypted item; null means no password is available.</param>
    /// <returns>The items; dispose it to zero the private keys.</returns>
    /// <exception cref="CryptoLoadException">The input is empty, unrecognised, malformed, unsupported, over a limit, or needs a password it did not get.</exception>
    public static LoadedItems Load(ReadOnlySpan<byte> data, Func<string, string?>? password = null) => CryptoLoader.Run(data, password);

    /// <summary>Loads the file at <paramref name="path"/>.</summary>
    /// <param name="path">The file. It is read whole, up to the 64 MiB limit.</param>
    /// <param name="password">See <see cref="Load(ReadOnlySpan{byte}, Func{string, string?}?)"/>.</param>
    /// <param name="cancellationToken">Checked before reading.</param>
    /// <exception cref="CryptoLoadException">See <see cref="Load(ReadOnlySpan{byte}, Func{string, string?}?)"/>; a file over the size limit gives <see cref="CryptoLoadError.LimitExceeded"/>.</exception>
    /// <exception cref="IOException">The file cannot be read.</exception>
    public static LoadedItems Load(string path, Func<string, string?>? password = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        cancellationToken.ThrowIfCancellationRequested();
        EnforceFileLimit(path);
        return CryptoLoader.Run(File.ReadAllBytes(path), password);
    }

    /// <summary>Loads everything from <paramref name="stream"/> to its end, up to the 64 MiB limit.</summary>
    /// <param name="stream">A readable stream; it is not closed.</param>
    /// <param name="password">See <see cref="Load(ReadOnlySpan{byte}, Func{string, string?}?)"/>.</param>
    /// <param name="cancellationToken">Checked while reading.</param>
    /// <exception cref="CryptoLoadException">See <see cref="Load(ReadOnlySpan{byte}, Func{string, string?}?)"/>.</exception>
    public static LoadedItems Load(Stream stream, Func<string, string?>? password = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var buffer = new MemoryStream();
        byte[] chunk = new byte[16 * 1024];
        int read;
        while ((read = stream.Read(chunk, 0, chunk.Length)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Append(buffer, chunk, read);
        }

        return CryptoLoader.Run(buffer.GetBuffer().AsSpan(0, (int)buffer.Length), password);
    }

    /// <summary>Like <see cref="Load(Stream, Func{string, string?}?, CancellationToken)"/>, reading asynchronously.</summary>
    public static async Task<LoadedItems> LoadAsync(Stream stream, Func<string, string?>? password = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var buffer = new MemoryStream();
        byte[] chunk = new byte[16 * 1024];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            Append(buffer, chunk, read);
        }

        return CryptoLoader.Run(buffer.GetBuffer().AsSpan(0, (int)buffer.Length), password);
    }

    /// <summary>Like <see cref="Load(string, Func{string, string?}?, CancellationToken)"/>, reading asynchronously.</summary>
    public static async Task<LoadedItems> LoadAsync(string path, Func<string, string?>? password = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        EnforceFileLimit(path);
        byte[] bytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        return CryptoLoader.Run(bytes, password);
    }

    /// <summary>Like <see cref="Load(ReadOnlySpan{byte}, Func{string, string?}?)"/>, returning false and the reasons instead of throwing.</summary>
    /// <param name="data">The file contents.</param>
    /// <param name="items">The items on success; null otherwise.</param>
    /// <param name="error">The failure, with the formats considered; null on success.</param>
    /// <param name="password">See <see cref="Load(ReadOnlySpan{byte}, Func{string, string?}?)"/>.</param>
    public static bool TryLoad(ReadOnlySpan<byte> data, out LoadedItems? items, out CryptoLoadException? error, Func<string, string?>? password = null)
    {
        try
        {
            items = CryptoLoader.Run(data, password);
            error = null;
            return true;
        }
        catch (CryptoLoadException ex)
        {
            items = null;
            error = ex;
            return false;
        }
    }

    /// <summary>Like <see cref="Load(string, Func{string, string?}?, CancellationToken)"/>, returning false and the reasons for bad input. I/O errors still throw.</summary>
    public static bool TryLoad(string path, out LoadedItems? items, out CryptoLoadException? error, Func<string, string?>? password = null)
    {
        ArgumentNullException.ThrowIfNull(path);
        if (!FileWithinLimit(path))
        {
            items = null;
            error = TooLarge();
            return false;
        }

        return TryLoad(File.ReadAllBytes(path), out items, out error, password);
    }

    private static void Append(MemoryStream buffer, byte[] chunk, int count)
    {
        if (buffer.Length + count > PkcsLimits.Default.MaxEncodedSize)
        {
            throw TooLarge();
        }

        buffer.Write(chunk, 0, count);
    }

    private static void EnforceFileLimit(string path)
    {
        if (!FileWithinLimit(path))
        {
            throw TooLarge();
        }
    }

    private static bool FileWithinLimit(string path) => new FileInfo(path).Length <= PkcsLimits.Default.MaxEncodedSize;

    private static CryptoLoadException TooLarge() => new(CryptoLoadError.LimitExceeded, $"The input is larger than the limit of {PkcsLimits.Default.MaxEncodedSize} bytes.");
}
