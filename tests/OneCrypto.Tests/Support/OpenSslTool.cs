using System.Diagnostics;

namespace OneCrypto.Tests.Support;

/// <summary>Runs the openssl command-line program as a black box. <c>ONECRYPTO_OPENSSL</c> names the binary (default: the one on PATH) and
/// <c>ONECRYPTO_OPENSSL_LIB</c> a library directory it needs.</summary>
internal static class OpenSslTool
{
    private static readonly Lazy<string?> Exe = new(Find);

    private static readonly Lazy<string> EmptyConfig = new(() =>
    {
        string path = Path.Combine(TempDir("conf"), "openssl.cnf");
        File.WriteAllText(path, "[req]\ndistinguished_name = dn\n[dn]\n");
        return path;
    });

    public static bool Available => Exe.Value is not null;

    public static void RequireOrSkip() => Assert.SkipUnless(Available, "openssl is not installed");

    private static readonly Lazy<(int Major, int Minor)?> Parsed = new(() =>
    {
        if (!Available)
        {
            return null;
        }

        // "OpenSSL 3.5.9 ..."; LibreSSL and other builds do not match and count as unknown.
        System.Text.RegularExpressions.Match m = System.Text.RegularExpressions.Regex.Match(Version, @"^OpenSSL (\d+)\.(\d+)");
        return m.Success ? (int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value)) : null;
    });

    /// <summary>True when the binary is OpenSSL of at least this version. LibreSSL and unrecognised builds are not.</summary>
    public static bool AtLeast(int major, int minor) => Parsed.Value is { } v && (v.Major, v.Minor).CompareTo((major, minor)) >= 0;

    /// <summary>Skips the test, naming the version found, unless the binary is OpenSSL at least this version. The tests that call it
    /// compare against behaviour first present in that release; a failure on a capable binary still fails.</summary>
    public static void RequireOrSkip(int major, int minor, string needs)
    {
        RequireOrSkip();
        Assert.SkipUnless(AtLeast(major, minor), $"needs OpenSSL {major}.{minor} or later ({needs}); found {Version}");
    }

    private static string? Find()
    {
        string? explicitPath = Environment.GetEnvironmentVariable("ONECRYPTO_OPENSSL");
        if (!string.IsNullOrEmpty(explicitPath))
        {
            return File.Exists(explicitPath) ? explicitPath : null;
        }

        foreach (string dir in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            string p = Path.Combine(dir, "openssl");
            if (File.Exists(p))
            {
                return p;
            }
        }

        return null;
    }

    public static string Version => Run("version").Output.Trim();

    public static (int Code, string Output) Run(params string[] args) => RunIn(null, args);

    public static (int Code, string Output) RunIn(string? dir, params string[] args)
    {
        var psi = new ProcessStartInfo(Exe.Value!) { RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = dir ?? Directory.GetCurrentDirectory() };
        string? lib = Environment.GetEnvironmentVariable("ONECRYPTO_OPENSSL_LIB");
        if (!string.IsNullOrEmpty(lib))
        {
            psi.Environment["LD_LIBRARY_PATH"] = lib;
            psi.Environment["DYLD_LIBRARY_PATH"] = lib;
        }

        if (Environment.GetEnvironmentVariable("OPENSSL_CONF") is null)
        {
            // A user-local build has no system configuration file; an empty one is what the commands here need.
            psi.Environment["OPENSSL_CONF"] = EmptyConfig.Value;
        }

        foreach (string a in args)
        {
            psi.ArgumentList.Add(a);
        }

        using Process p = Process.Start(psi)!;
        Task<string> err = p.StandardError.ReadToEndAsync();
        string o = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        return (p.ExitCode, o + err.Result);
    }

    /// <summary>True when this openssl lists the algorithm among its public-key algorithms (for example ML-DSA-65).</summary>
    public static bool Has(string algorithm) => Available && Run("list", "-public-key-algorithms").Output.Contains(algorithm, StringComparison.OrdinalIgnoreCase);

    public static string TempDir(string name)
    {
        string dir = Path.Combine(Environment.GetEnvironmentVariable("TMPDIR") ?? Path.GetTempPath(), "onecrypto-x509", name);
        Directory.CreateDirectory(dir);
        return dir;
    }
}
