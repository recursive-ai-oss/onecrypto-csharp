using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.GnuPG;

/// <summary>
/// A GnuPG home directory read from disk: the public keys in <c>pubring.kbx</c> (or the older <c>pubring.gpg</c>), the secret key files in
/// <c>private-keys-v1.d</c> and the owner trust in <c>trustdb.gpg</c>. This is a thin layer over the format readers; it only reads, never
/// writes, never starts gpg-agent and does no network I/O. It reads each file when asked and keeps no handle open.
/// </summary>
/// <remarks>
/// Files are read whole, so a keybox is limited by <see cref="GnuPGLimits.MaxBlobLength"/> per blob and a key file by
/// <see cref="GnuPGLimits.MaxKeyFileLength"/>; a file that is a symbolic link is read through the link, as GnuPG does.
/// </remarks>
public sealed class GnuPGHome
{
    private const int MaxKeyFiles = 1 << 16;
    private const long MaxRingFileLength = 1L << 30;

    private GnuPGHome(string path, GnuPGLimits limits)
    {
        Path = path;
        Limits = limits;
    }

    /// <summary>The directory.</summary>
    public string Path { get; }

    /// <summary>The limits applied to every file read.</summary>
    public GnuPGLimits Limits { get; }

    /// <summary>
    /// The directory GnuPG would use: the <c>GNUPGHOME</c> environment variable, else <c>.gnupg</c> in the user's home directory
    /// (on Windows <c>%APPDATA%\gnupg</c>).
    /// </summary>
    public static string DefaultPath()
    {
        string? env = Environment.GetEnvironmentVariable("GNUPGHOME");
        if (!string.IsNullOrEmpty(env))
        {
            return env;
        }

        if (OperatingSystem.IsWindows())
        {
            return System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "gnupg");
        }

        return System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".gnupg");
    }

    /// <summary>Opens a home directory for reading.</summary>
    /// <param name="path">The directory.</param>
    /// <param name="limits">Limits; null for <see cref="GnuPGLimits.Default"/>.</param>
    /// <exception cref="DirectoryNotFoundException">The directory does not exist.</exception>
    public static GnuPGHome Open(string path, GnuPGLimits? limits = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        string full = System.IO.Path.GetFullPath(path);
        if (!Directory.Exists(full))
        {
            throw new DirectoryNotFoundException("The GnuPG home directory does not exist.");
        }

        return new GnuPGHome(full, limits ?? GnuPGLimits.Default);
    }

    /// <summary>True when the home has a keybox (<c>pubring.kbx</c>).</summary>
    public bool HasKeybox => File.Exists(System.IO.Path.Combine(Path, "pubring.kbx"));

    /// <summary>The keybox, or null when the home has none.</summary>
    /// <exception cref="GnuPGFormatException">The keybox is malformed.</exception>
    public Keybox? ReadKeybox() =>
        TryReadFile("pubring.kbx", MaxRingFileLength, out byte[] data) ? Keybox.Parse(data, Limits) : null;

    /// <summary>
    /// The public keys of the home: the OpenPGP blobs of <c>pubring.kbx</c> when it exists, otherwise the keys of the legacy
    /// <c>pubring.gpg</c>, otherwise none. When both files exist the keybox is what GnuPG 2.1 and later use, so it is the one read.
    /// </summary>
    /// <exception cref="GnuPGFormatException">The keybox is malformed.</exception>
    /// <exception cref="OpenPgpParseException">The legacy keyring or a keybox blob holds malformed OpenPGP data.</exception>
    public IReadOnlyList<TransferableKey> ReadPublicKeys()
    {
        Keybox? kbx = ReadKeybox();
        if (kbx is not null)
        {
            return [.. kbx.OpenPgpBlobs.Select(b => b.ReadKey())];
        }

        return TryReadFile("pubring.gpg", MaxRingFileLength, out byte[] ring) ? LegacyKeyring.Read(ring) : [];
    }

    /// <summary>The trust database, or null when <c>trustdb.gpg</c> does not exist.</summary>
    /// <exception cref="GnuPGFormatException">The file is malformed.</exception>
    public TrustDb? ReadTrustDb() =>
        TryReadFile("trustdb.gpg", MaxRingFileLength, out byte[] data) ? TrustDb.Parse(data, Limits) : null;

    /// <summary>
    /// The secret key files of <c>private-keys-v1.d</c>, parsed but still locked, in file-name order. A file that does not parse is
    /// skipped and reported through <paramref name="skipped"/> (name and reason) so one damaged file does not hide the others.
    /// </summary>
    /// <param name="skipped">Receives one entry per file that was not a readable key file.</param>
    /// <returns>The file names (without directory) and their parsed contents; empty when the directory does not exist.</returns>
    /// <exception cref="GnuPGFormatException">The directory holds more than 65,536 key files.</exception>
    public IReadOnlyList<KeyValuePair<string, GnuPGKeyFile>> ReadKeyFiles(out IReadOnlyList<KeyValuePair<string, GnuPGFailure>> skipped)
    {
        var ok = new List<KeyValuePair<string, GnuPGKeyFile>>();
        var bad = new List<KeyValuePair<string, GnuPGFailure>>();
        skipped = bad;
        string dir = System.IO.Path.Combine(Path, "private-keys-v1.d");
        if (!Directory.Exists(dir))
        {
            return ok;
        }

        foreach (string file in Directory.EnumerateFiles(dir, "*.key").OrderBy(f => f, StringComparer.Ordinal))
        {
            if (ok.Count + bad.Count >= MaxKeyFiles)
            {
                throw new GnuPGFormatException(GnuPGError.LimitExceeded, 0, "too many key files");
            }

            string name = System.IO.Path.GetFileName(file);
            var info = new FileInfo(file);
            if (info.Length > Limits.MaxKeyFileLength)
            {
                bad.Add(new(name, new GnuPGFailure(GnuPGError.LimitExceeded, 0, "key file too large")));
                continue;
            }

            if (GnuPGKeyFile.TryParse(File.ReadAllBytes(file), out GnuPGKeyFile? kf, out GnuPGFailure failure, Limits))
            {
                ok.Add(new(name, kf!));
            }
            else
            {
                bad.Add(new(name, failure));
            }
        }

        return ok;
    }

    /// <summary>
    /// The secret key file for an OpenPGP key: the file whose public parameter (the RSA modulus or the elliptic-curve point) equals the key's,
    /// or null when the home holds none. Matching by public value means the lookup works for primary keys and subkeys alike.
    /// </summary>
    /// <param name="key">A public key or subkey packet of a certificate in this home.</param>
    /// <returns>The still-locked key file, or null.</returns>
    public GnuPGKeyFile? FindKeyFile(KeyPacket key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Material.Values.Count == 0)
        {
            return null;
        }

        ReadOnlySpan<byte> wanted = Strip(key.Material.Values[0].Span);
        foreach (KeyValuePair<string, GnuPGKeyFile> f in ReadKeyFiles(out _))
        {
            ReadOnlySpan<byte> have = Strip(f.Value.GetPublicParameter(f.Value.Algorithm == "rsa" ? "n" : "q").Span);
            if (!have.IsEmpty && have.SequenceEqual(wanted)) // public data
            {
                return f.Value;
            }
        }

        return null;
    }

    private bool TryReadFile(string name, long maxLength, out byte[] data)
    {
        string path = System.IO.Path.Combine(Path, name);
        data = [];
        if (!File.Exists(path))
        {
            return false;
        }

        if (new FileInfo(path).Length > maxLength)
        {
            throw new GnuPGFormatException(GnuPGError.LimitExceeded, 0, name + " is too large");
        }

        data = File.ReadAllBytes(path);
        return true;
    }

    private static ReadOnlySpan<byte> Strip(ReadOnlySpan<byte> v)
    {
        while (v.Length > 0 && v[0] == 0)
        {
            v = v[1..];
        }

        return v;
    }
}
