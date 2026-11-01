using System.Reflection;

namespace RecursiveAI.OneCrypto.Cli.Sop;

/// <summary>
/// The Stateless OpenPGP command-line interface (draft-dkg-openpgp-stateless-cli): option parsing, dispatch and exit codes. The subcommands that need
/// only the packet layer are implemented; the others answer with UNSUPPORTED_SUBCOMMAND until the message and key operations exist.
/// </summary>
internal static class SopApp
{
    /// <summary>The draft this tool targets, with a tilde while it is incomplete.</summary>
    public const string SpecName = "~draft-dkg-openpgp-stateless-cli-16";

    // The subcommands the draft defines (section 5), so that a known-but-unwritten one is told apart from a misspelling in the message.
    private static readonly HashSet<string> KnownSubcommands =
    [
        "version", "list-profiles", "generate-key", "change-key-password", "revoke-key", "extract-cert", "update-key", "merge-certs",
        "certify-userid", "validate-userid", "sign", "verify", "encrypt", "decrypt", "inline-detach", "inline-verify", "inline-sign",
        "armor", "dearmor",
    ];

    public static string ProductVersion { get; } = typeof(SopApp).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0";

    /// <summary>Runs one invocation (the arguments after <c>sop</c>) and returns the exit code.</summary>
    public static int Run(string[] args, SopIo io)
    {
        try
        {
            Options o = Options.Parse(args);
            if (o.Subcommand is null)
            {
                throw new SopException(SopExit.UnsupportedSubcommand, "no subcommand given");
            }

            switch (o.Subcommand)
            {
                case "version":
                    return Version(o, io);
                case "list-profiles":
                    return ListProfiles(o);
                case "armor":
                    return PacketCommands.RunArmor(o, io);
                case "dearmor":
                    return PacketCommands.RunDearmor(o, io);
                case "extract-cert":
                    return PacketCommands.RunExtractCert(o, io);
                case "inline-detach":
                    return InlineDetach.Run(o, io);
                default:
                    throw new SopException(SopExit.UnsupportedSubcommand,
                        KnownSubcommands.Contains(o.Subcommand) ? $"'{o.Subcommand}' is not implemented yet" : $"unknown subcommand '{o.Subcommand}'");
            }
        }
        catch (SopException e)
        {
            io.Stderr.WriteLine("onecrypto sop: " + e.Message);
            return e.ExitCode;
        }
        catch (RecursiveAI.OneCrypto.OpenPgp.Packets.OpenPgpParseException e)
        {
            io.Stderr.WriteLine("onecrypto sop: bad data: " + e.Message);
            return SopExit.BadData;
        }
        catch (IOException e)
        {
            io.Stderr.WriteLine("onecrypto sop: i/o error: " + e.Message);
            return SopExit.UnspecifiedFailure;
        }
    }

    private static int Version(Options o, SopIo io)
    {
        int modes = new[] { o.Flag("--backend"), o.Flag("--extended"), o.Flag("--sop-spec"), o.Flag("--sopv") }.Count(static x => x);
        o.RejectUnknown("--backend", "--extended", "--sop-spec", "--sopv");
        if (modes > 1)
        {
            throw new SopException(SopExit.IncompatibleOptions, "--backend, --extended, --sop-spec and --sopv are mutually exclusive");
        }

        o.NoPositionals();
        if (o.Flag("--sopv"))
        {
            // Only verify and inline-verify make sopv; neither exists yet, so the subset is not provided.
            throw new SopException(SopExit.UnsupportedOption, "the sopv subset is not provided yet");
        }

        string text;
        if (o.Flag("--backend"))
        {
            text = "RecursiveAI.OneCrypto.OpenPgp " + ProductVersion;
        }
        else if (o.Flag("--sop-spec"))
        {
            text = SpecName + "\nThe packet-level subcommands (armor, dearmor, extract-cert, inline-detach) only.";
        }
        else if (o.Flag("--extended"))
        {
            text = "onecrypto " + ProductVersion + "\nRecursiveAI.OneCrypto.OpenPgp " + ProductVersion + "\nRunning on .NET " + Environment.Version;
        }
        else
        {
            text = "onecrypto " + ProductVersion;
        }

        io.Stdout.Write(System.Text.Encoding.UTF8.GetBytes(text + "\n"));
        return SopExit.Ok;
    }

    private static int ListProfiles(Options o)
    {
        o.RejectUnknown();
        if (o.Positionals.Count != 1)
        {
            throw new SopException(SopExit.MissingArg, "list-profiles takes one subcommand name");
        }

        string sub = o.Positionals[0];
        if (!KnownSubcommands.Contains(sub))
        {
            throw new SopException(SopExit.UnsupportedSubcommand, $"unknown subcommand '{sub}'");
        }

        // generate-key and encrypt are the subcommands that take a profile; they are not written yet.
        throw sub is "generate-key" or "encrypt"
            ? new SopException(SopExit.UnsupportedSubcommand, $"'{sub}' is not implemented yet")
            : new SopException(SopExit.UnsupportedProfile, $"'{sub}' does not take a profile");
    }
}

/// <summary>
/// The arguments of one invocation: the subcommand, its <c>--name</c> and <c>--name=value</c> options, and the positionals. A bare <c>--</c> ends option
/// parsing, so what follows is positional even when it starts with dashes.
/// </summary>
internal sealed class Options
{
    private readonly Dictionary<string, string?> _values = new(StringComparer.Ordinal);
    private readonly HashSet<string> _used = new(StringComparer.Ordinal);
    private readonly List<string> _positionals = [];

    private Options()
    {
    }

    public string? Subcommand { get; private set; }

    public IReadOnlyList<string> Positionals => _positionals;

    public static Options Parse(string[] args)
    {
        var o = new Options();
        bool optionsEnded = false;
        foreach (string a in args)
        {
            if (!optionsEnded && a == "--")
            {
                optionsEnded = true;
            }
            else if (!optionsEnded && a.StartsWith("--", StringComparison.Ordinal))
            {
                int eq = a.IndexOf('=', StringComparison.Ordinal);
                string name = eq < 0 ? a : a[..eq];
                if (name == "--debug")
                {
                    continue;
                }

                if (o._values.ContainsKey(name))
                {
                    throw new SopException(SopExit.UnsupportedOption, "the option is repeated: " + name);
                }

                o._values[name] = eq < 0 ? null : a[(eq + 1)..];
            }
            else if (o.Subcommand is null)
            {
                o.Subcommand = a;
            }
            else
            {
                o._positionals.Add(a);
            }
        }

        return o;
    }

    /// <summary>True when the boolean option is present. Giving it a value is refused.</summary>
    public bool Flag(string name)
    {
        if (!_values.TryGetValue(name, out string? v))
        {
            return false;
        }

        _used.Add(name);
        return v is null ? true : throw new SopException(SopExit.UnsupportedOption, name + " takes no value");
    }

    /// <summary>The value of an option given as <c>--name=value</c>, or null when absent.</summary>
    public string? Value(string name)
    {
        if (!_values.TryGetValue(name, out string? v))
        {
            return null;
        }

        _used.Add(name);
        return v ?? throw new SopException(SopExit.MissingArg, name + " needs a value");
    }

    /// <summary>Fails with UNSUPPORTED_OPTION for an option nobody asked about, or one of those named here but not read yet.</summary>
    public void RejectUnknown(params string[] allowed)
    {
        foreach (string name in _values.Keys)
        {
            if (!_used.Contains(name) && Array.IndexOf(allowed, name) < 0)
            {
                throw new SopException(SopExit.UnsupportedOption, "unsupported option " + name);
            }
        }
    }

    public void NoPositionals()
    {
        if (_positionals.Count > 0)
        {
            throw new SopException(SopExit.UnsupportedOption, "unexpected argument '" + _positionals[0] + "'");
        }
    }
}
