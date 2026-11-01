using System.Globalization;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.OpenPgp.GnuPG;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.CertD;

/// <summary>
/// An opaque value that changes whenever the stored certificate changes. Compare tags for equality only. Here it is the file's last write
/// time and length.
/// </summary>
/// <param name="Value">The tag text.</param>
public readonly record struct CertTag(string Value)
{
    /// <inheritdoc/>
    public override string ToString() => Value;
}

/// <summary>One certificate (or, for the special name <c>trust-root</c>, possibly a secret key) read from the directory.</summary>
public sealed class CertEntry
{
    internal CertEntry(string name, CertTag tag, ReadOnlyMemory<byte> data)
    {
        Name = name;
        Tag = tag;
        Data = data;
    }

    /// <summary>The name it was found under: the lower-case hexadecimal fingerprint, or <c>trust-root</c>.</summary>
    public string Name { get; }

    /// <summary>The tag at the time it was read.</summary>
    public CertTag Tag { get; }

    /// <summary>The stored octets: the OpenPGP packets of exactly one transferable key, binary, as stored.</summary>
    public ReadOnlyMemory<byte> Data { get; }

    /// <summary>Decodes the stored packets.</summary>
    /// <param name="limits">Limits for the packet reader; null for <see cref="OpenPgpLimits.Default"/>.</param>
    /// <exception cref="OpenPgpParseException">The data is not exactly one well-formed transferable key.</exception>
    public TransferableKey ReadKey(OpenPgpLimits? limits = null) => TransferableKey.Parse(PacketParser.ParseAll(Data, limits));
}

/// <summary>
/// The shared OpenPGP certificate directory (draft-nwjw-openpgp-cert-d-00): one binary certificate per file, found by its lower-case hexadecimal
/// fingerprint as <c>xx/rest</c>, the special name <c>trust-root</c>, an exclusive lock on <c>writelock</c> while writing, and atomic
/// replacement. Names that start with an underscore belong to other implementations' extensions (Sequoia keeps its signature cache there) and are
/// left alone. Readers need no lock: every file is replaced as a whole.
/// </summary>
public sealed class CertDirectory
{
    /// <summary>The special name of the trust-root certificate or key.</summary>
    public const string TrustRoot = "trust-root";

    private const string WriteLockName = "writelock";

    private CertDirectory(string path)
    {
        Path = path;
    }

    /// <summary>The directory.</summary>
    public string Path { get; }

    /// <summary>How long <see cref="Insert"/> waits for the write lock before giving up. Default 30 seconds.</summary>
    public TimeSpan LockTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// The default location: the <c>PGP_CERT_D</c> environment variable when set, otherwise <c>pgp.cert.d</c> under the platform's data directory
    /// (<c>$XDG_DATA_HOME</c> or <c>~/.local/share</c>; <c>~/Library/Application Support</c> on macOS; the roaming application data folder on Windows).
    /// </summary>
    public static string DefaultPath()
    {
        string? env = Environment.GetEnvironmentVariable("PGP_CERT_D");
        if (!string.IsNullOrEmpty(env))
        {
            return env;
        }

        if (OperatingSystem.IsWindows())
        {
            return System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "pgp.cert.d");
        }

        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (OperatingSystem.IsMacOS())
        {
            return System.IO.Path.Combine(home, "Library", "Application Support", "pgp.cert.d");
        }

        string? xdg = Environment.GetEnvironmentVariable("XDG_DATA_HOME");
        return System.IO.Path.Combine(string.IsNullOrEmpty(xdg) ? System.IO.Path.Combine(home, ".local", "share") : xdg, "pgp.cert.d");
    }

    /// <summary>Opens a directory as a store.</summary>
    /// <param name="path">The directory.</param>
    /// <param name="create">True to create it (and its parents) when missing; false to require that it exists.</param>
    /// <exception cref="DirectoryNotFoundException">The directory does not exist and <paramref name="create"/> is false.</exception>
    /// <exception cref="IOException">The path exists and is not a directory.</exception>
    public static CertDirectory Open(string path, bool create = true)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        if (File.Exists(path))
        {
            throw new IOException("The path is a file, not a certificate directory.");
        }

        if (!Directory.Exists(path))
        {
            if (!create)
            {
                throw new DirectoryNotFoundException("The certificate directory does not exist.");
            }

            if (OperatingSystem.IsWindows())
            {
                Directory.CreateDirectory(path);
            }
            else
            {
                Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
        }

        return new CertDirectory(System.IO.Path.GetFullPath(path));
    }

    /// <summary>True when <paramref name="name"/> is a fingerprint (32, 40 or 64 hexadecimal digits, either case) or <see cref="TrustRoot"/>.</summary>
    /// <param name="name">The name.</param>
    public static bool IsValidName(string name) => name == TrustRoot || IsFingerprint(name);

    /// <summary>The path of a name relative to the directory: <c>trust-root</c>, or the first two digits, a separator and the rest, in lower case.</summary>
    /// <param name="name">A fingerprint or <see cref="TrustRoot"/>.</param>
    /// <exception cref="GnuPGFormatException">The name is neither.</exception>
    public static string RelativePath(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (name == TrustRoot)
        {
            return name;
        }

        if (!IsFingerprint(name))
        {
            throw new GnuPGFormatException(GnuPGError.BadSyntax, 0, "a certificate name is a hexadecimal fingerprint or trust-root");
        }

        string lower = name.ToLowerInvariant();
        return lower[..2] + System.IO.Path.DirectorySeparatorChar + lower[2..];
    }

    /// <summary>Reads a certificate.</summary>
    /// <param name="name">A fingerprint (any case) or <see cref="TrustRoot"/>.</param>
    /// <returns>The entry, or null when the store has none under that name.</returns>
    /// <exception cref="GnuPGFormatException">The name is not valid, or the file under a fingerprint is not a certificate with that fingerprint.</exception>
    public CertEntry? Get(string name)
    {
        string full = System.IO.Path.Combine(Path, RelativePath(name));
        byte[] data;
        CertTag tag;
        try
        {
            // The tag is taken before the read: a replacement in between makes the next comparison differ, which is the safe direction.
            tag = TagOf(full);
            data = File.ReadAllBytes(full);
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }

        string key = name == TrustRoot ? name : name.ToLowerInvariant();
        var entry = new CertEntry(key, tag, data);
        if (name != TrustRoot)
        {
            VerifyFingerprint(entry);
        }

        return entry;
    }

    /// <summary>Reads a certificate only if it changed since <paramref name="tag"/> was taken.</summary>
    /// <param name="tag">The tag from an earlier read.</param>
    /// <param name="name">A fingerprint or <see cref="TrustRoot"/>.</param>
    /// <returns>The entry when the stored file differs from the tag or the tag is for a missing file; null when it is unchanged or missing.</returns>
    public CertEntry? GetIfChanged(CertTag tag, string name)
    {
        string full = System.IO.Path.Combine(Path, RelativePath(name));
        try
        {
            if (TagOf(full) == tag)
            {
                return null;
            }
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }

        return Get(name);
    }

    /// <summary>Lists the certificates by fingerprint (not <see cref="TrustRoot"/>), skipping everything that is not a fingerprint path.</summary>
    public IEnumerable<CertEntry> Enumerate()
    {
        if (!Directory.Exists(Path))
        {
            yield break;
        }

        foreach (string dir in Directory.EnumerateDirectories(Path).OrderBy(d => d, StringComparer.Ordinal))
        {
            string prefix = System.IO.Path.GetFileName(dir);
            if (prefix.Length != 2 || !IsLowerHex(prefix))
            {
                continue;
            }

            foreach (string file in Directory.EnumerateFiles(dir).OrderBy(f => f, StringComparer.Ordinal))
            {
                string name = prefix + System.IO.Path.GetFileName(file);
                if (!IsFingerprint(name) || name != name.ToLowerInvariant())
                {
                    continue;
                }

                CertEntry? e = Get(name);
                if (e is not null)
                {
                    yield return e;
                }
            }
        }
    }

    /// <summary>
    /// Inserts a certificate under its primary fingerprint: takes the write lock, merges with the stored copy if there is one, and replaces
    /// the file atomically. When the merge adds nothing, nothing is written and the tag stays.
    /// </summary>
    /// <param name="certificate">The certificate. A secret key is stored as its public certificate.</param>
    /// <param name="merge">The merge, given the stored certificate (null if none) and the new one; null for <see cref="CertMerge.Merge"/>.</param>
    /// <exception cref="TimeoutException">The write lock was not obtained within <see cref="LockTimeout"/>.</exception>
    public CertEntry Insert(TransferableKey certificate, Func<TransferableKey?, TransferableKey, TransferableKey>? merge = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        string name = certificate.Primary.FingerprintHex.ToLowerInvariant();
        return InsertAs(name, certificate.ToPublic(), merge, expectFingerprint: true);
    }

    /// <summary>Stores a certificate or secret key as the trust root, merging with the stored one like <see cref="Insert"/>.</summary>
    /// <param name="key">The certificate or key.</param>
    /// <param name="merge">The merge; null for <see cref="CertMerge.Merge"/> (which requires the same primary key as the stored one).</param>
    public CertEntry InsertTrustRoot(TransferableKey key, Func<TransferableKey?, TransferableKey, TransferableKey>? merge = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        return InsertAs(TrustRoot, key, merge, expectFingerprint: false);
    }

    private CertEntry InsertAs(string name, TransferableKey incoming, Func<TransferableKey?, TransferableKey, TransferableKey>? merge, bool expectFingerprint)
    {
        Directory.CreateDirectory(Path);
        using (AcquireWriteLock())
        {
            string full = System.IO.Path.Combine(Path, RelativePath(name));
            TransferableKey? existing = null;
            CertEntry? have = Get(name);
            if (have is not null)
            {
                existing = have.ReadKey();
            }

            TransferableKey result;
            if (merge is not null)
            {
                result = merge(existing, incoming);
            }
            else
            {
                result = CertMerge.Merge(existing, incoming, out _);
            }

            if (expectFingerprint && !string.Equals(result.Primary.FingerprintHex, name, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("The merge changed the primary key.");
            }

            if (existing is not null && ReferenceEquals(result, existing))
            {
                return have!;
            }

            using var ms = new MemoryStream();
            result.WriteTo(ms);
            byte[] bytes = ms.ToArray();
            if (have is not null && bytes.AsSpan().SequenceEqual(have.Data.Span)) // public data
            {
                return have;
            }

            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(full)!);
            string temp = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(full)!, ".tmp-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8)));
            try
            {
                using (var fs = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    fs.Write(bytes);
                    fs.Flush(flushToDisk: true);
                }

                // Same directory, so the rename is atomic on POSIX and a replacing move on Windows.
                File.Move(temp, full, overwrite: true);
            }
            catch
            {
                File.Delete(temp);
                throw;
            }

            return new CertEntry(name, TagOf(full), bytes);
        }
    }

    // Exclusive lock on <dir>/writelock, created if missing (draft §3.3). On POSIX the runtime takes flock(LOCK_EX) when a file is opened with
    // FileShare.None, the very call other implementations use on the same file, so the locks exclude each other; it does not block, so wait by
    // polling. On Windows LockFile is used through FileStream.Lock.
    private FileStream AcquireWriteLock()
    {
        string path = System.IO.Path.Combine(Path, WriteLockName);
        long start = Environment.TickCount64;
        int delay = 2;
        while (true)
        {
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    var fs = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite);
                    try
                    {
                        fs.Lock(0, long.MaxValue);
                        return fs;
                    }
                    catch
                    {
                        fs.Dispose();
                        throw;
                    }
                }

                return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException) when (Environment.TickCount64 - start < LockTimeout.TotalMilliseconds)
            {
                Thread.Sleep(delay);
                delay = Math.Min(delay * 2, 50);
            }
            catch (IOException e)
            {
                throw new TimeoutException("The certificate directory's write lock is held by another process.", e);
            }
        }
    }

    private static CertTag TagOf(string fullPath)
    {
        var info = new FileInfo(fullPath);
        if (!info.Exists)
        {
            throw new FileNotFoundException(null, fullPath);
        }

        return new CertTag(info.LastWriteTimeUtc.Ticks.ToString(CultureInfo.InvariantCulture) + "-" + info.Length.ToString(CultureInfo.InvariantCulture));
    }

    private static void VerifyFingerprint(CertEntry entry)
    {
        TransferableKey key;
        try
        {
            key = entry.ReadKey();
        }
        catch (OpenPgpParseException e)
        {
            throw new GnuPGFormatException("The file stored under " + entry.Name + " is not an OpenPGP certificate.", e);
        }

        // Draft §3.4: a certificate stored under a fingerprint must have that fingerprint.
        if (!string.Equals(key.Primary.FingerprintHex, entry.Name, StringComparison.OrdinalIgnoreCase))
        {
            throw new GnuPGFormatException(GnuPGError.BadOpenPgp, 0, "the certificate stored under " + entry.Name + " has another fingerprint");
        }
    }

    private static bool IsFingerprint(string s) => s.Length is 32 or 40 or 64 && s.All(char.IsAsciiHexDigit);

    private static bool IsLowerHex(string s) => s.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
}
