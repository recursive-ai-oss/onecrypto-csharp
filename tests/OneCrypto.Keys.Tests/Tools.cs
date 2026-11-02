using System.Diagnostics;

namespace OneCrypto.Keys.Tests;

/// <summary>Runs command-line oracles (openssl, sqop) as black boxes.</summary>
internal static class Tools
{
    internal static string? OpenSsl => Environment.GetEnvironmentVariable("ONECRYPTO_OPENSSL") is { Length: > 0 } p && File.Exists(p) ? p : Find("openssl");

    internal static string? Sqop => Environment.GetEnvironmentVariable("ONECRYPTO_SQOP") is { Length: > 0 } p && File.Exists(p) ? p : null;

    internal static void RequireOpenSsl() => Assert.SkipUnless(OpenSsl is not null, "openssl is not installed");

    internal static void RequireSqop() => Assert.SkipUnless(Sqop is not null, "sqop is not installed (ONECRYPTO_SQOP)");

    private static string? Find(string name)
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

    /// <summary>Runs a program, feeding it a file as standard input when one is given, and returns its exit code, standard output and standard error.</summary>
    internal static (int Code, byte[] Out, string Error) Run(string exe, string? stdin, params string[] args)
    {
        var psi = new ProcessStartInfo(exe) { RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = stdin is not null };
        foreach (string a in args)
        {
            psi.ArgumentList.Add(a);
        }

        string? lib = Environment.GetEnvironmentVariable("ONECRYPTO_OPENSSL_LIB");
        if (!string.IsNullOrEmpty(lib) && exe == OpenSsl)
        {
            psi.Environment["LD_LIBRARY_PATH"] = lib;
            psi.Environment["DYLD_LIBRARY_PATH"] = lib;
        }

        using Process p = Process.Start(psi)!;
        Task<string> err = p.StandardError.ReadToEndAsync();
        using var o = new MemoryStream();
        Task copy = p.StandardOutput.BaseStream.CopyToAsync(o);
        if (stdin is not null)
        {
            using (FileStream f = File.OpenRead(stdin))
            {
                f.CopyTo(p.StandardInput.BaseStream);
            }

            p.StandardInput.Close();
        }

        copy.Wait();
        p.WaitForExit();
        return (p.ExitCode, o.ToArray(), err.Result);
    }

    internal static string Pem(string label, byte[] der) =>
        $"-----BEGIN {label}-----\n{Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks)}\n-----END {label}-----\n";
}
