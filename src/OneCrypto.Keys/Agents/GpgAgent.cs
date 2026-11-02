using System.Security.Cryptography;
using System.Text;

namespace RecursiveAI.OneCrypto.Keys.Agents;

/// <summary>How to reach and talk to a gpg-agent. Every property has a default that works for the user's own agent.</summary>
public sealed class GpgAgentOptions
{
    /// <summary>The agent's socket. When null, <see cref="GpgAgent.LocateSocket"/> works it out from <see cref="HomeDirectory"/>.</summary>
    public string? SocketPath { get; init; }

    /// <summary>The GnuPG home directory whose agent to use. Null means <c>GNUPGHOME</c>, then <c>~/.gnupg</c>.</summary>
    public string? HomeDirectory { get; init; }

    /// <summary>How long to wait for the socket to accept a connection. Default 5 seconds.</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// How long one operation may take after connecting, passphrase prompts included, before the call fails with <see cref="AgentUnavailableException"/>.
    /// Default 10 minutes; <see cref="Timeout.InfiniteTimeSpan"/> waits for ever (the call's <see cref="CancellationToken"/> still works).
    /// </summary>
    public TimeSpan OperationTimeout { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Tell the agent which terminal and display the user is at, so that a passphrase prompt (pinentry) can appear there: <c>GPG_TTY</c>, <c>TERM</c>,
    /// <c>DISPLAY</c> and <c>XAUTHORITY</c> are sent when set, as GnuPG itself does. Default true. The agent's own configuration decides which pinentry runs.
    /// </summary>
    public bool ForwardEnvironment { get; init; } = true;

    /// <summary>
    /// Check every signature the agent returns against the key's public key before handing it on, so that a faulty or hostile agent cannot pass off a bad
    /// signature. Default true.
    /// </summary>
    public bool VerifySignatures { get; init; } = true;

    /// <summary>The most octets one agent reply may take, over all its lines. Default 256 KiB; replies are a few kilobytes.</summary>
    public int MaxReplyBytes { get; init; } = 256 * 1024;
}

/// <summary>Where a key listed by the agent keeps its secret.</summary>
public enum GpgAgentKeyProtection
{
    /// <summary>The agent could not say.</summary>
    Unknown = 0,
    /// <summary>A passphrase protects the key file; using it makes the agent prompt unless the passphrase is cached.</summary>
    Passphrase = 1,
    /// <summary>The key file is not protected.</summary>
    None = 2,
}

/// <summary>A secret key the agent holds, as <c>KEYINFO</c> reports it.</summary>
/// <param name="Keygrip">The 40-digit hexadecimal keygrip that names the key to the agent.</param>
/// <param name="Protection">How the key file is protected.</param>
/// <param name="IsOnToken">True when the secret lives on a smartcard or token the agent reaches through its card daemon.</param>
/// <param name="CardSerial">The token's serial number when <paramref name="IsOnToken"/>, else null.</param>
/// <param name="PassphraseCached">True when the agent has the key's passphrase cached, so a signature will not prompt.</param>
public sealed record GpgAgentKeyInfo(string Keygrip, GpgAgentKeyProtection Protection, bool IsOnToken, string? CardSerial, bool PassphraseCached);

/// <summary>
/// A client for gpg-agent, GnuPG's key agent, over its local Assuan socket. The private keys stay in the agent: this class lists them, reads their public parts, and has the
/// agent sign, decrypt and agree for them, so passphrase prompts (pinentry), caching and smartcards behave exactly as for GnuPG itself.
/// </summary>
/// <remarks>
/// <para>Each operation opens its own short connection, so one client is safe to share between threads. Nothing is fetched or started: if no agent runs on the socket,
/// calls throw <see cref="AgentUnavailableException"/> (GnuPG starts the agent on demand; run <c>gpgconf --launch gpg-agent</c> first).</para>
/// <para>What the agent can do depends on the key: RSA signs with PKCS #1 v1.5 (SHA-1, SHA-256, SHA-384, SHA-512) and decrypts with PKCS #1 v1.5 and OAEP; the NIST and
/// Brainpool curves sign with ECDSA and agree with ECDH; Ed25519 and Ed448 sign messages of up to the size the agent accepts in one inquiry (2048 octets for gpg-agent 2.4);
/// Cv25519 and Cv448 agree. RSA-PSS is not offered: the agent has no PSS operation in the versions this was written against.</para>
/// </remarks>
[System.Runtime.Versioning.UnsupportedOSPlatform("browser")]
public sealed class GpgAgentClient
{
    private readonly GpgAgentOptions _options;

    /// <summary>Creates a client. Nothing connects until the first operation.</summary>
    /// <param name="options">Socket, timeouts and behaviour; null means the defaults.</param>
    public GpgAgentClient(GpgAgentOptions? options = null)
    {
        _options = options ?? new GpgAgentOptions();
    }

    internal GpgAgentOptions Options => _options;

    /// <summary>The socket this client talks to: the option if set, else what <see cref="GpgAgent.LocateSocket"/> finds.</summary>
    /// <exception cref="AgentUnavailableException">No socket could be found.</exception>
    public string SocketPath => _options.SocketPath ?? GpgAgent.LocateSocket(_options.HomeDirectory) ?? throw new AgentUnavailableException(null, "No gpg-agent socket was found; is the agent running?");

    /// <summary>Lists the secret keys the agent holds (<c>KEYINFO --list</c>).</summary>
    /// <exception cref="AgentException">The agent is not there or answered badly.</exception>
    public IReadOnlyList<GpgAgentKeyInfo> ListKeys() => ListKeysAsync().AsTask().GetAwaiter().GetResult();

    /// <summary>The async form of <see cref="ListKeys"/>.</summary>
    public async ValueTask<IReadOnlyList<GpgAgentKeyInfo>> ListKeysAsync(CancellationToken cancellationToken = default)
    {
        AssuanReply reply = await RunAsync(async (s, ct) => await s.CommandAsync("KEYINFO --list", null, ct).ConfigureAwait(false), cancellationToken).ConfigureAwait(false);
        var list = new List<GpgAgentKeyInfo>();
        foreach ((string kw, string text) in reply.Status)
        {
            if (kw != "KEYINFO")
            {
                continue;
            }

            // KEYINFO <keygrip> <type> <serialno> <idstr> <cached> <protection> <fpr> <ttl> <flags>; "-" stands for "none".
            string[] f = text.Split(' ');
            if (f.Length < 6 || !IsKeygrip(f[0]))
            {
                continue;
            }

            list.Add(new GpgAgentKeyInfo(
                f[0].ToUpperInvariant(),
                f[5] switch { "P" => GpgAgentKeyProtection.Passphrase, "C" => GpgAgentKeyProtection.None, _ => GpgAgentKeyProtection.Unknown },
                f[1] == "T",
                f[2] == "-" ? null : f[2],
                f[4] == "1"));
        }

        return list;
    }

    /// <summary>
    /// Opens the key with the given keygrip: reads its public part from the agent and returns the key object matching its algorithm (<see cref="GpgAgentRsaKey"/>,
    /// <see cref="GpgAgentEcKey"/>, <see cref="GpgAgentEdKey"/> or <see cref="GpgAgentMontgomeryKey"/>).
    /// </summary>
    /// <param name="keygrip">The 40-digit hexadecimal keygrip.</param>
    /// <param name="pinentryDescription">Text for the passphrase prompt when the agent asks (<c>SETKEYDESC</c>); null lets the agent word it.</param>
    /// <exception cref="ArgumentException">The keygrip is not 40 hexadecimal digits.</exception>
    /// <exception cref="AgentKeyNotFoundException">The agent has no such key.</exception>
    /// <exception cref="AlgorithmNotSupportedException">The key is of a kind this client does not handle.</exception>
    public GpgAgentKey GetKey(string keygrip, string? pinentryDescription = null) => GetKeyAsync(keygrip, pinentryDescription).AsTask().GetAwaiter().GetResult();

    /// <summary>The async form of <see cref="GetKey"/>.</summary>
    public async ValueTask<GpgAgentKey> GetKeyAsync(string keygrip, string? pinentryDescription = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keygrip);
        if (!IsKeygrip(keygrip))
        {
            throw new ArgumentException("A keygrip is 40 hexadecimal digits.", nameof(keygrip));
        }

        string grip = keygrip.ToUpperInvariant();
        AssuanReply reply;
        try
        {
            reply = await RunAsync(async (s, ct) => await s.CommandAsync("READKEY " + grip, null, ct).ConfigureAwait(false), cancellationToken).ConfigureAwait(false);
        }
        catch (AgentRefusedException e) when (GpgAgentKey.IsNoKey(e))
        {
            throw new AgentKeyNotFoundException($"The agent has no key with keygrip {grip}.");
        }

        return GpgAgentKey.FromPublicKeySExp(this, grip, reply.Data, pinentryDescription);
    }

    /// <summary>Finds the agent's key for a public key (a certificate's, an OpenPGP key's): reads every listed key's public part and compares. Returns null when none matches.</summary>
    /// <param name="publicKey">The public key to look for.</param>
    /// <param name="pinentryDescription">Text for the passphrase prompt, as for <see cref="GetKey"/>.</param>
    public GpgAgentKey? FindKey(PublicKeyInfo publicKey, string? pinentryDescription = null) => FindKeyAsync(publicKey, pinentryDescription).AsTask().GetAwaiter().GetResult();

    /// <summary>The async form of <see cref="FindKey"/>.</summary>
    public async ValueTask<GpgAgentKey?> FindKeyAsync(PublicKeyInfo publicKey, string? pinentryDescription = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        foreach (GpgAgentKeyInfo info in await ListKeysAsync(cancellationToken).ConfigureAwait(false))
        {
            GpgAgentKey key;
            try
            {
                key = await GetKeyAsync(info.Keygrip, pinentryDescription, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception e) when (e is AgentKeyNotFoundException or AlgorithmNotSupportedException or AgentRefusedException)
            {
                // A key the agent lists but will not describe, or of a kind we do not handle, cannot be the one asked for.
                continue;
            }

            if (key.PublicKey.Equals(publicKey))
            {
                return key;
            }

            key.Dispose();
        }

        return null;
    }

    /// <summary>Runs <paramref name="body"/> on a fresh connection with the operation timeout, mapping a timeout to <see cref="AgentUnavailableException"/>.</summary>
    internal async Task<T> RunAsync<T>(Func<AssuanSession, CancellationToken, Task<T>> body, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string path = SocketPath;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (_options.OperationTimeout != Timeout.InfiniteTimeSpan)
        {
            timeout.CancelAfter(_options.OperationTimeout);
        }

        try
        {
            using AssuanSession session = await AssuanSession.ConnectAsync(path, _options.ConnectTimeout, _options.MaxReplyBytes, timeout.Token).ConfigureAwait(false);
            if (_options.ForwardEnvironment)
            {
                await ForwardEnvironmentAsync(session, timeout.Token).ConfigureAwait(false);
            }

            return await body(session, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new AgentUnavailableException(path, $"The agent did not finish within {_options.OperationTimeout}.");
        }
    }

    private static async Task ForwardEnvironmentAsync(AssuanSession session, CancellationToken cancellationToken)
    {
        // The same four settings gpg sends so that a pinentry can find the user's terminal or screen. An agent that does not accept one just says no.
        (string Option, string Variable)[] map = [("ttyname", "GPG_TTY"), ("ttytype", "TERM"), ("display", "DISPLAY"), ("xauthority", "XAUTHORITY")];
        foreach ((string option, string variable) in map)
        {
            string? value = Environment.GetEnvironmentVariable(variable);
            if (string.IsNullOrEmpty(value) || value.AsSpan().IndexOfAny('\r', '\n') >= 0 || value.Length > 400)
            {
                continue;
            }

            try
            {
                await session.CommandAsync($"OPTION {option}={value}", null, cancellationToken).ConfigureAwait(false);
            }
            catch (AgentRefusedException)
            {
                // Not every agent build knows every option.
            }
        }
    }

    internal static bool IsKeygrip(string s)
    {
        if (s.Length != 40)
        {
            return false;
        }

        foreach (char c in s)
        {
            if (!char.IsAsciiHexDigit(c))
            {
                return false;
            }
        }

        return true;
    }

    internal static string Escape(string text)
    {
        var sb = new StringBuilder(text.Length);
        foreach (char c in text)
        {
            switch (c)
            {
                case '%': sb.Append("%25"); break;
                case '\r': sb.Append("%0D"); break;
                case '\n': sb.Append("%0A"); break;
                default: sb.Append(c); break;
            }
        }

        return sb.ToString();
    }

    internal static void Wipe(byte[]? secret)
    {
        if (secret is not null)
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }
}

/// <summary>Where gpg-agent's socket is.</summary>
[System.Runtime.Versioning.UnsupportedOSPlatform("browser")]
public static class GpgAgent
{
    /// <summary>
    /// Finds the socket of the agent for a GnuPG home directory the way GnuPG names it: for the default home (<c>~/.gnupg</c>) <c>$XDG_RUNTIME_DIR/gnupg/S.gpg-agent</c>; for any other home
    /// <c>$XDG_RUNTIME_DIR/gnupg/d.&lt;hash&gt;/S.gpg-agent</c> where the hash is 24 characters of z-base-32 over the first 15 octets of the SHA-1 of the absolute home path; and
    /// <c>S.gpg-agent</c> inside the home itself when there is no runtime directory. Without <c>XDG_RUNTIME_DIR</c> the Linux per-user directory <c>/run/user/&lt;uid&gt;</c> is used when it exists.
    /// A socket-redirection file (a regular file starting with <c>%Assuan%</c> and a <c>socket=</c> line) is followed.
    /// </summary>
    /// <param name="homeDirectory">The home; null means <c>GNUPGHOME</c>, then <c>~/.gnupg</c>.</param>
    /// <returns>The path of the first candidate that exists, or null.</returns>
    public static string? LocateSocket(string? homeDirectory = null)
    {
        string home = ResolveHome(homeDirectory, out bool isDefault);
        var candidates = new List<string>();
        string? runtime = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR");
        if (string.IsNullOrEmpty(runtime))
        {
            runtime = LinuxRuntimeDirectory();
        }

        if (!string.IsNullOrEmpty(runtime))
        {
            string g = Path.Combine(runtime, "gnupg");
            candidates.Add(isDefault ? Path.Combine(g, "S.gpg-agent") : Path.Combine(g, "d." + HomeHash(home), "S.gpg-agent"));
        }

        candidates.Add(Path.Combine(home, "S.gpg-agent"));
        foreach (string candidate in candidates)
        {
            string? resolved = Resolve(candidate);
            if (resolved is not null)
            {
                return resolved;
            }
        }

        return null;
    }

    /// <summary>The 24-character directory-name suffix GnuPG derives from a home directory path: z-base-32 of the first 15 octets of the SHA-1 of the path.</summary>
    /// <param name="absoluteHome">The absolute path of the home, without a trailing separator.</param>
    public static string HomeHash(string absoluteHome)
    {
        ArgumentNullException.ThrowIfNull(absoluteHome);
#pragma warning disable CA5350 // The name is defined as a SHA-1 prefix by GnuPG; it labels a directory and protects nothing.
        byte[] digest = SHA1.HashData(Encoding.UTF8.GetBytes(absoluteHome));
#pragma warning restore CA5350
        const string alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769";
        var sb = new StringBuilder(24);
        for (int i = 0; i < 24; i++)
        {
            int bit = i * 5, idx = bit / 8, shift = bit % 8;
            int window = (digest[idx] << 8) | (idx + 1 < 15 ? digest[idx + 1] : 0);
            sb.Append(alphabet[(window >> (11 - shift)) & 31]);
        }

        return sb.ToString();
    }

    private static string ResolveHome(string? homeDirectory, out bool isDefault)
    {
        string? h = homeDirectory ?? Environment.GetEnvironmentVariable("GNUPGHOME");
        string def = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".gnupg");
        if (string.IsNullOrEmpty(h))
        {
            isDefault = true;
            return def;
        }

        string full = Path.GetFullPath(h).TrimEnd(Path.DirectorySeparatorChar);
        isDefault = full == Path.GetFullPath(def).TrimEnd(Path.DirectorySeparatorChar);
        return full;
    }

    private static string? LinuxRuntimeDirectory()
    {
        if (!OperatingSystem.IsLinux())
        {
            return null;
        }

        try
        {
            foreach (string line in File.ReadLines("/proc/self/status"))
            {
                if (line.StartsWith("Uid:", StringComparison.Ordinal))
                {
                    string[] f = line.Split('\t', StringSplitOptions.RemoveEmptyEntries);
                    string dir = "/run/user/" + f[1];
                    return Directory.Exists(dir) ? dir : null;
                }
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        return null;
    }

    private static string? Resolve(string path)
    {
        try
        {
            FileInfo info = new(path);
            if (!info.Exists)
            {
                return null;
            }

            if (info.Length == 0)
            {
                // A socket shows up as a zero-length file.
                return path;
            }

            if (info.Length is > 0 and < 512)
            {
                // A redirection file: "%Assuan%" on the first line, then "socket=<path>".
                string[] lines = File.ReadAllLines(path);
                if (lines.Length >= 2 && lines[0].Trim() == "%Assuan%")
                {
                    foreach (string l in lines)
                    {
                        if (l.StartsWith("socket=", StringComparison.Ordinal))
                        {
                            return l[7..].Trim();
                        }
                    }
                }
            }

            return path;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }
}
