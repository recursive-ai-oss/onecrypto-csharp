using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;

namespace OneCrypto.Keys.Tests;

/// <summary>Runs oracle programs as black boxes and finds the repository's scripts.</summary>
internal static class Tools
{
    public static string RepoRoot([CallerFilePath] string here = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(here)!, "..", ".."));

    /// <summary>A short scratch directory (Unix socket paths are limited to about 100 characters).</summary>
    public static string ShortTemp(string name)
    {
        string root = Environment.GetEnvironmentVariable("ONECRYPTO_SHORT_TMP") ?? Environment.GetEnvironmentVariable("TMPDIR") ?? Path.GetTempPath();
        string dir = Path.Combine(root, "oca-" + name + "-" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static (int Code, byte[] Out, string Err) Run(string exe, IEnumerable<string> args, IDictionary<string, string?>? env = null, byte[]? stdin = null, string? dir = null, int timeoutSeconds = 120)
    {
        var psi = new ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = stdin is not null,
            WorkingDirectory = dir ?? Directory.GetCurrentDirectory(),
        };
        foreach (string a in args)
        {
            psi.ArgumentList.Add(a);
        }

        if (env is not null)
        {
            foreach ((string k, string? v) in env)
            {
                if (v is null)
                {
                    psi.Environment.Remove(k);
                }
                else
                {
                    psi.Environment[k] = v;
                }
            }
        }

        using Process p = Process.Start(psi)!;
        Task<string> err = p.StandardError.ReadToEndAsync();
        var outMs = new MemoryStream();
        Task copy = p.StandardOutput.BaseStream.CopyToAsync(outMs);
        if (stdin is not null)
        {
            p.StandardInput.BaseStream.Write(stdin);
            p.StandardInput.Close();
        }

        if (!p.WaitForExit(timeoutSeconds * 1000))
        {
            p.Kill(entireProcessTree: true);
            throw new TimeoutException($"{exe} did not finish in {timeoutSeconds} s");
        }

        copy.Wait();
        return (p.ExitCode, outMs.ToArray(), err.Result);
    }

    public static string Text(byte[] b) => Encoding.UTF8.GetString(b);

    public static string? Find(string name)
    {
        foreach (string dir in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            string p = Path.Combine(dir, name);
            if (File.Exists(p))
            {
                return p;
            }
        }

        return null;
    }
}

/// <summary>
/// A throwaway GnuPG home with a running gpg-agent, built by <c>tools/oracles/gpg-agent-home.sh</c> with the gpg binary named by <c>ONECRYPTO_GPG</c> (default <c>/usr/bin/gpg</c>).
/// Library path for a private build comes from <c>LD_LIBRARY_PATH</c> in the environment.
/// </summary>
public sealed class GpgAgentFixture : IDisposable
{
    public sealed record KeyEntry(string Name, string Fingerprint, string SignGrip, string EncryptGrip);

    private readonly string _bin = string.Empty;
    private readonly string? _skip;

    public GpgAgentFixture()
    {
        string gpg = Environment.GetEnvironmentVariable("ONECRYPTO_GPG") ?? "/usr/bin/gpg";
        if (!File.Exists(gpg))
        {
            _skip = "no gpg binary (set ONECRYPTO_GPG)";
            Home = Gpg = string.Empty;
            return;
        }

        Gpg = gpg;
        _bin = Path.GetDirectoryName(gpg)!;
        Home = Path.Combine(Tools.ShortTemp("gh"), "home");
        (int code, byte[] o, string e) = Tools.Run("bash", [Path.Combine(Tools.RepoRoot(), "tools", "oracles", "gpg-agent-home.sh"), _bin, Home]);
        if (code != 0)
        {
            throw new InvalidOperationException("gpg-agent-home.sh failed: " + Tools.Text(o) + e);
        }

        Keys = [.. File.ReadAllLines(Path.Combine(Home, "keys.tsv")).Select(l => l.Split('\t')).Select(f => new KeyEntry(f[0], f[1], f[2], f.Length > 3 ? f[3] : string.Empty))];
        Version = File.ReadAllText(Path.Combine(Home, "VERSION")).Trim();
        Gpgconf("--launch", "gpg-agent");
    }

    public string Gpg { get; }

    public string Home { get; }

    public string Version { get; } = string.Empty;

    public IReadOnlyList<KeyEntry> Keys { get; } = [];

    public KeyEntry Key(string name) => Keys.Single(k => k.Name == name);

    public void RequireGpg() => Assert.SkipWhen(_skip is not null, _skip ?? string.Empty);

    public IDictionary<string, string?> Env => new Dictionary<string, string?> { ["GNUPGHOME"] = Home };

    public string ExpectedSocket => Tools.Text(Gpgconf("--list-dirs", "agent-socket").Out).Trim();

    public (int Code, byte[] Out, string Err) Gpgconf(params string[] args) =>
        Tools.Run(Path.Combine(_bin, "gpgconf"), ["--homedir", Home, .. args]);

    public (int Code, byte[] Out, string Err) GpgRun(byte[]? stdin, params string[] args) =>
        Tools.Run(Gpg, ["--homedir", Home, "--batch", "--no-tty", "--yes", .. args], stdin: stdin);

    public (int Code, byte[] Out, string Err) ConnectAgent(string command) =>
        Tools.Run(Path.Combine(_bin, "gpg-connect-agent"), ["--homedir", Home, command, "/bye"]);

    public void SetPinentry(string mode) => File.WriteAllText(Path.Combine(Home, "pinentry-mode"), mode);

    public void Dispose()
    {
        if (_skip is null)
        {
            Gpgconf("--kill", "all");
            try
            {
                Directory.Delete(Path.GetDirectoryName(Home)!, recursive: true);
            }
            catch (IOException)
            {
                // best effort: the scratch directory is under the temp root anyway
            }
        }
    }
}
