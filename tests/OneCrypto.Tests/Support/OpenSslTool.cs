using System.Diagnostics;

namespace OneCrypto.Tests.Support;

/// <summary>Runs the openssl command-line program as a black box. <c>ONECRYPTO_OPENSSL</c> names the binary (default: the one on PATH) and
/// <c>ONECRYPTO_OPENSSL_LIB</c> a library directory it needs.</summary>
internal static class OpenSslTool
{
    private static readonly Lazy<string?> Exe = new(Find);

    public static bool Available => Exe.Value is not null;

    public static void RequireOrSkip() => Assert.SkipUnless(Available, "openssl is not installed");

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
