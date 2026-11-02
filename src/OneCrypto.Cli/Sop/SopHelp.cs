using System.Text;

namespace RecursiveAI.OneCrypto.Cli.Sop;

/// <summary>
/// Help text for <c>onecrypto</c> and <c>onecrypto sop</c>. The Stateless OpenPGP draft defines no help option, so this is a convenience: it lists the
/// subcommands of draft section 5 with their options, and exits 0 like any other successful answer.
/// </summary>
internal static class SopHelp
{
    // Subcommand, arguments and options as the draft writes them (section 5), then a one-line description.
    private static readonly (string Name, string Usage, string Summary)[] Subcommands =
    [
        ("version", "[--extended|--backend|--sop-spec|--sopv]", "print the tool's name and version"),
        ("list-profiles", "<subcommand>", "list the profiles a subcommand accepts (generate-key, encrypt)"),
        ("generate-key", "[--no-armor] [--profile=P] [--signing-only] [--with-key-password=FILE] [USERID...]", "make a secret key"),
        ("change-key-password", "[--no-armor] [--old-key-password=FILE...] [--new-key-password=FILE]", "change or remove the password of secret keys (stdin)"),
        ("revoke-key", "[--no-armor] [--with-key-password=FILE...]", "make a revocation certificate for secret keys (stdin)"),
        ("extract-cert", "[--no-armor]", "turn secret keys (stdin) into certificates"),
        ("update-key", "[--no-armor] [--signing-only] [--no-added-capabilities] [--revoke-deprecated-keys] [--with-key-password=FILE...] [--merge-certs=CERT...]", "extend the validity and capabilities of secret keys (stdin)"),
        ("merge-certs", "[--no-armor] [CERT...]", "merge certificates (stdin) with the updates given as arguments"),
        ("certify-userid", "[--no-armor] --userid=USERID [--with-key-password=FILE...] [--no-require-self-sig] KEY...", "certify User IDs of certificates (stdin)"),
        ("validate-userid", "[--addr-spec-only] [--validate-at=DATE] USERID CERTS...", "check that CERTS carry a valid certification of USERID by the authority certificates (stdin)"),
        ("sign", "[--no-armor] [--as=binary|text] [--micalg-out=FILE] [--with-key-password=FILE...] KEY...", "make detached signatures over stdin"),
        ("verify", "[--not-before=DATE] [--not-after=DATE] SIGNATURES CERTS...", "check detached signatures over stdin; prints one line per good signature"),
        ("encrypt", "[--no-armor] [--as=binary|text] [--profile=P] [--with-password=FILE...] [--sign-with=KEY...] [--with-key-password=FILE...] [CERT...]", "encrypt stdin to passwords and certificates"),
        ("decrypt", "[--session-key-out=FILE] [--with-session-key=FILE...] [--with-password=FILE...] [--verify-out=FILE|--verifications-out=FILE] [--verify-with=CERT...] [--verify-not-before=DATE] [--verify-not-after=DATE] [KEY...]", "decrypt stdin"),
        ("inline-sign", "[--no-armor] [--as=binary|text|clearsigned] [--with-key-password=FILE...] KEY...", "sign stdin into one message"),
        ("inline-verify", "[--no-armor] [--verifications-out=FILE] [--not-before=DATE] [--not-after=DATE] CERTS...", "check a signed message (stdin); prints the data"),
        ("inline-detach", "[--no-armor] --signatures-out=FILE", "split a signed message (stdin) into data and signatures"),
        ("armor", "", "add ASCII armor to binary data (stdin)"),
        ("dearmor", "", "remove ASCII armor from data (stdin)"),
    ];

    /// <summary>True for the arguments that ask for help: <c>help</c>, <c>--help</c> or <c>-h</c> first.</summary>
    public static bool IsHelpRequest(string[] args) => args.Length > 0 && args[0] is "help" or "--help" or "-h";

    /// <summary>The help for <c>onecrypto sop</c>, or for one subcommand when it is the first argument and the second asks for help.</summary>
    public static string ForSop(string[] args, bool sopv)
    {
        if (args.Length >= 2 && (args[1] is "--help" or "-h" || args[0] == "help"))
        {
            string name = args[0] == "help" ? args[1] : args[0];
            foreach ((string Name, string Usage, string Summary) in Subcommands)
            {
                if (Name == name)
                {
                    return Wrap($"Usage: onecrypto {(sopv ? "sopv" : "sop")} {Name} {Usage}", 4) + $"\n\n{Wrap(Summary + ".", 0)}\n";
                }
            }
        }

        var sb = new StringBuilder();
        sb.Append(sopv ? "Usage: onecrypto sopv <subcommand> [options] [arguments]\n\n" : "Usage: onecrypto sop <subcommand> [options] [arguments]\n\n");
        sb.Append(Wrap("The Stateless OpenPGP command line (draft-dkg-openpgp-stateless-cli). Data goes in on standard input and out on standard output; keys, certificates, signatures and passwords are given as file names. Exit codes are the draft's.", 0));
        sb.Append("\n\nSubcommands:\n");
        foreach ((string Name, string Usage, string Summary) in Subcommands)
        {
            if (sopv && Name is not ("version" or "verify" or "inline-verify" or "validate-userid"))
            {
                continue;
            }

            sb.Append(Wrap("  " + Name.PadRight(20) + Summary, 22)).Append('\n');
        }

        sb.Append("\n`onecrypto sop <subcommand> --help` shows a subcommand's options.\n");
        return sb.ToString();
    }

    /// <summary>The widest line any help text has, so it reads in an 80-column terminal.</summary>
    internal const int MaxWidth = 80;

    /// <summary>Breaks <paramref name="line"/> at spaces so no line is longer than <see cref="MaxWidth"/>; continuation lines are indented by <paramref name="hang"/> columns. A word longer than the room stays whole.</summary>
    internal static string Wrap(string line, int hang)
    {
        int lead = 0;
        while (lead < line.Length && line[lead] == ' ')
        {
            lead++;
        }

        var sb = new StringBuilder(line.Length + 16);
        sb.Append(' ', lead);
        int col = lead;
        bool atLineStart = true;
        foreach (string word in line[lead..].Split(' '))
        {
            // An empty word is one of several spaces in a row, which a list uses as a column gap: keep it.
            if (word.Length == 0)
            {
                sb.Append(' ');
                col++;
                continue;
            }

            if (!atLineStart && col + word.Length > MaxWidth)
            {
                while (sb[^1] == ' ')
                {
                    sb.Length--;
                }

                sb.Append('\n').Append(' ', hang);
                col = hang;
                atLineStart = true;
            }
            else if (!atLineStart && sb[^1] != ' ')
            {
                sb.Append(' ');
                col++;
            }

            sb.Append(word);
            col += word.Length;
            atLineStart = false;
        }

        return sb.ToString();
    }

    /// <summary>The help for the tool itself.</summary>
    public static string ForTool() =>
        "Usage: onecrypto <command> [arguments]\n\n"
        + "Commands:\n"
        + Wrap("  sop <subcommand>       the Stateless OpenPGP command line: sign, verify, encrypt, decrypt, generate-key and the rest", 25) + "\n"
        + Wrap("  sopv <subcommand>      the verification-only subset of sop (version, verify, inline-verify, validate-userid)", 25) + "\n"
        + Wrap("  pgp authenticate       judge how well a User ID is authenticated by the web of trust", 25) + "\n\n"
        + "`onecrypto sop --help` lists the sop subcommands.\n";
}
