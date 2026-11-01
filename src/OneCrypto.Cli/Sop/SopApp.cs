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

    /// <summary>The version of the sopv subset (draft section 3) this tool provides in full.</summary>
    public const string SopvVersion = "1.2";

    // The subcommands sopv allows (draft section 3).
    private static readonly HashSet<string> SopvSubcommands = ["version", "verify", "inline-verify", "validate-userid"];

    public static string ProductVersion { get; } = typeof(SopApp).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0";

    /// <summary>Runs one invocation (the arguments after <c>sop</c>) and returns the exit code.</summary>
    public static int Run(string[] args, SopIo io) => Run(args, io, sopvOnly: false);

    /// <summary>Runs one invocation; with <paramref name="sopvOnly"/> only the verification subset (draft section 3) is available, as when the tool is run as <c>sopv</c>.</summary>
    public static int Run(string[] args, SopIo io, bool sopvOnly)
    {
        try
        {
            Options o = Options.Parse(args);
            if (o.Subcommand is null)
            {
                throw new SopException(SopExit.UnsupportedSubcommand, "no subcommand given");
            }

            if (sopvOnly && !SopvSubcommands.Contains(o.Subcommand))
            {
                throw new SopException(SopExit.UnsupportedSubcommand, $"'{o.Subcommand}' is not part of sopv");
            }

            switch (o.Subcommand)
            {
                case "version":
                    return Version(o, io);
                case "list-profiles":
                    return ListProfiles(o, io);
                case "armor":
                    return PacketCommands.RunArmor(o, io);
                case "dearmor":
                    return PacketCommands.RunDearmor(o, io);
                case "extract-cert":
                    return PacketCommands.RunExtractCert(o, io);
                case "inline-detach":
                    return InlineDetach.Run(o, io);
                case "sign":
                    return MessageCommands.RunSign(o, io);
                case "verify":
                    return MessageCommands.RunVerify(o, io);
                case "inline-sign":
                    return MessageCommands.RunInlineSign(o, io);
                case "inline-verify":
                    return MessageCommands.RunInlineVerify(o, io);
                case "encrypt":
                    return MessageCommands.RunEncrypt(o, io);
                case "decrypt":
                    return MessageCommands.RunDecrypt(o, io);
                case "generate-key":
                    return KeyCommands.RunGenerateKey(o, io);
                case "change-key-password":
                    return KeyCommands.RunChangeKeyPassword(o, io);
                case "revoke-key":
                    return KeyCommands.RunRevokeKey(o, io);
                case "update-key":
                    return KeyCommands.RunUpdateKey(o, io);
                case "merge-certs":
                    return KeyCommands.RunMergeCerts(o, io);
                case "certify-userid":
                    return KeyCommands.RunCertifyUserId(o, io);
                case "validate-userid":
                    return KeyCommands.RunValidateUserId(o, io);
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
        catch (RecursiveAI.OneCrypto.OpenPgp.PgpException e)
        {
            io.Stderr.WriteLine("onecrypto sop: " + e.Message);
            return e.Failure switch
            {
                RecursiveAI.OneCrypto.OpenPgp.PgpFailure.KeyIsProtected => SopExit.KeyIsProtected,
                RecursiveAI.OneCrypto.OpenPgp.PgpFailure.CannotDecrypt or RecursiveAI.OneCrypto.OpenPgp.PgpFailure.NoDecryptionKey => SopExit.CannotDecrypt,
                RecursiveAI.OneCrypto.OpenPgp.PgpFailure.MalformedMessage or RecursiveAI.OneCrypto.OpenPgp.PgpFailure.LimitExceeded => SopExit.BadData,
                RecursiveAI.OneCrypto.OpenPgp.PgpFailure.Unsupported => SopExit.UnsupportedAsymmetricAlgo,
                _ => SopExit.UnspecifiedFailure,
            };
        }
        catch (RecursiveAI.OneCrypto.AlgorithmNotSupportedException e)
        {
            io.Stderr.WriteLine("onecrypto sop: " + e.Message);
            return SopExit.UnsupportedAsymmetricAlgo;
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
            // Draft section 3: version, verify and inline-verify make sopv 1.0; validate-userid came with 1.2. All four are provided.
            io.Stdout.Write(System.Text.Encoding.UTF8.GetBytes(SopvVersion + "\n"));
            return SopExit.Ok;
        }

        string text;
        if (o.Flag("--backend"))
        {
            text = "RecursiveAI.OneCrypto.OpenPgp " + ProductVersion;
        }
        else if (o.Flag("--sop-spec"))
        {
            text = SpecName + "\nSubcommands: all of them; update-key never generates a replacement key, so --revoke-deprecated-keys has no effect.";
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

    private static int ListProfiles(Options o, SopIo io)
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

        if (sub == "encrypt")
        {
            // §5.1: the first line names the default profile.
            io.Stdout.Write(System.Text.Encoding.UTF8.GetBytes("rfc9580: choose the message format from the recipients' keys (SEIPD v2 with AEAD where they allow it)\nrfc4880: always use SEIPD v1 with an MDC, for recipients that predate RFC 9580\n"));
            return SopExit.Ok;
        }

        if (sub == "generate-key")
        {
            io.Stdout.Write(System.Text.Encoding.UTF8.GetBytes(KeyCommands.ProfileList()));
            return SopExit.Ok;
        }

        throw new SopException(SopExit.UnsupportedProfile, $"'{sub}' does not take a profile");
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
    private readonly Dictionary<string, List<string?>> _multi = new(StringComparer.Ordinal);

    private static readonly HashSet<string> MultiOptions =
        ["--with-password", "--with-key-password", "--with-session-key", "--sign-with", "--verify-with", "--old-key-password", "--userid", "--merge-certs"];

    // Options that take a value. The draft writes them as --name=value; other implementations, and the interoperability suite, also give the
    // value as the next argument, so that form is read for these names only (a flag followed by a positional must stay a flag).
    private static readonly HashSet<string> ValueOptions =
    [
        "--as", "--for", "--micalg-out", "--not-after", "--not-before", "--profile", "--session-key-out", "--signatures-out", "--verifications-out",
        "--verify-not-after", "--verify-not-before", "--verify-out", "--with-password", "--with-key-password", "--with-session-key", "--sign-with", "--verify-with",
        "--old-key-password", "--new-key-password", "--userid", "--merge-certs", "--validate-at",
    ];

    private Options()
    {
    }

    public string? Subcommand { get; private set; }

    public IReadOnlyList<string> Positionals => _positionals;

    public static Options Parse(string[] args)
    {
        var o = new Options();
        bool optionsEnded = false;
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
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

                string? val = eq < 0 ? null : a[(eq + 1)..];
                if (val is null && ValueOptions.Contains(name) && i + 1 < args.Length)
                {
                    val = args[++i];
                }

                if (MultiOptions.Contains(name))
                {
                    // Options the draft allows more than once keep every value, in order.
                    if (!o._multi.TryGetValue(name, out List<string?>? many))
                    {
                        o._multi[name] = many = [];
                    }

                    many.Add(val);
                    continue;
                }

                if (o._values.ContainsKey(name))
                {
                    throw new SopException(SopExit.UnsupportedOption, "the option is repeated: " + name);
                }

                o._values[name] = val;
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

    /// <summary>All values of an option that may repeat (<c>--with-password</c> and the like), in order. Each needs a value.</summary>
    public IReadOnlyList<string> Values(string name)
    {
        if (!_multi.TryGetValue(name, out List<string?>? many))
        {
            return [];
        }

        _used.Add(name);
        return many.Select(v => v ?? throw new SopException(SopExit.MissingArg, name + " needs a value")).ToList();
    }

    /// <summary>Fails with UNSUPPORTED_OPTION for an option nobody asked about, or one of those named here but not read yet.</summary>
    public void RejectUnknown(params string[] allowed)
    {
        foreach (string name in _values.Keys.Concat(_multi.Keys))
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
