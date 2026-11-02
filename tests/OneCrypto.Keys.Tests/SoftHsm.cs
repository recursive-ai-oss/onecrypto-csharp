using System.Diagnostics;
using RecursiveAI.OneCrypto.Keys.Pkcs11;

namespace OneCrypto.Keys.Tests;

/// <summary>
/// A throwaway SoftHSM2 token store for the tests, used as a black box. <c>ONECRYPTO_SOFTHSM2_MODULE</c> names the module and
/// <c>ONECRYPTO_SOFTHSM2_UTIL</c> the <c>softhsm2-util</c> program, and <c>SOFTHSM2_CONF</c> a configuration that points at an empty token directory
/// (<c>tools/oracles/softhsm2.sh --env</c> exports all three); without them the tests skip.
/// Tokens, PINs and keys are generated for the test run in a scratch directory and deleted with it.
/// </summary>
internal static class SoftHsm
{
    internal const string UserPin = "4711";
    internal const string SoPin = "12345678";
    internal const string MainToken = "u-main";

    /// <summary>A token for the tests that log out or fail logins: the login state belongs to the token, so they must not share one with tests running beside them.</summary>
    internal const string AuthToken = "u-auth";

    private static readonly Lazy<string?> Dir = new(Setup);

    internal static string? Module => Environment.GetEnvironmentVariable("ONECRYPTO_SOFTHSM2_MODULE") is { Length: > 0 } m && File.Exists(m) ? m : null;

    internal static string? Util => Environment.GetEnvironmentVariable("ONECRYPTO_SOFTHSM2_UTIL") is { Length: > 0 } u && File.Exists(u) ? u : null;

    internal static bool Available => Module is not null && Util is not null;

    internal static void RequireOrSkip() => Assert.SkipUnless(Available && Dir.Value is not null, "SoftHSM2 is not installed (tools/oracles/softhsm2.sh --env)");

    /// <summary>The scratch directory of the token store and the files the tests make.</summary>
    internal static string Work
    {
        get
        {
            RequireOrSkip();
            return Dir.Value!;
        }
    }

    private static string? Setup()
    {
        if (!Available)
        {
            return null;
        }

        // The module reads SOFTHSM2_CONF when it starts, so the environment of the test process carries it (tools/oracles/softhsm2.sh --env makes a fresh store).
        string? conf = Environment.GetEnvironmentVariable("SOFTHSM2_CONF");
        if (conf is null || !File.Exists(conf))
        {
            return null;
        }

        string dir = Path.GetDirectoryName(conf)!;
        foreach (string label in new[] { MainToken, AuthToken, "u-import" })
        {
            Util_(["--init-token", "--free", "--label", label, "--so-pin", SoPin, "--pin", UserPin]);
        }

        return dir;
    }

    internal static (int Code, string Output) Util_(params string[] args)
    {
        var psi = new ProcessStartInfo(Util!) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string a in args)
        {
            psi.ArgumentList.Add(a);
        }

        // The packaged tool looks for the module at its system path, which a user-local install does not have.
        psi.ArgumentList.Add("--module");
        psi.ArgumentList.Add(Module!);

        using Process p = Process.Start(psi)!;
        Task<string> err = p.StandardError.ReadToEndAsync();
        string o = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        int code = p.ExitCode;
        if (code != 0 && args[0] == "--init-token")
        {
            throw new InvalidOperationException("softhsm2-util failed: " + o + err.Result);
        }

        return (code, o + err.Result);
    }

    /// <summary>The slot holding the token with this label.</summary>
    internal static Pkcs11Slot SlotOf(Pkcs11Module module, string label) =>
        module.GetSlots().Single(s => s.GetTokenInfo().Label == label);

    /// <summary>Opens the module and a logged-in read/write session on a token.</summary>
    internal static (Pkcs11Module Module, Pkcs11Session Session) Open(string token = MainToken)
    {
        RequireOrSkip();
        Pkcs11Module module = Pkcs11Module.Load(Module!);
        Pkcs11Session s = SlotOf(module, token).OpenSession(readWrite: true);
        s.Login(UserPin);
        return (module, s);
    }

    private static int _counter;

    /// <summary>A fresh label and ID, so tests never find each other's keys.</summary>
    internal static (string Label, byte[] Id) Fresh(string prefix)
    {
        int n = Interlocked.Increment(ref _counter);
        return ($"{prefix}-{n}", [(byte)(n >> 8), (byte)n, 0x42]);
    }
}
