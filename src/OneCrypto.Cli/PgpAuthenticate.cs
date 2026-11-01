using System.Globalization;
using System.Text;
using RecursiveAI.OneCrypto.OpenPgp;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.OpenPgp.Trust;

namespace RecursiveAI.OneCrypto.Cli;

/// <summary>
/// <c>onecrypto pgp authenticate --root FINGERPRINT... [--userid TEXT] [--time ISO-8601] CERTIFICATE-FILE...</c>:
/// asks the flow-based web of trust whether each User ID of the given certificates is bound to its certificate, from the given roots.
/// Files may be binary or armored. Without <c>--userid</c> every User ID of every certificate that is not a root is checked; with it, only
/// that text. Prints one verdict per User ID with the paths that carry the trust. Exit 0 when every checked binding is fully
/// authenticated, 1 when one is not, 2 for bad arguments or unreadable input.
/// </summary>
internal static class PgpAuthenticate
{
    public static int Run(string[] args, TextWriter output, TextWriter error)
    {
        var roots = new List<string>();
        var files = new List<string>();
        string? userId = null;
        DateTimeOffset at = DateTimeOffset.UtcNow;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--root" when i + 1 < args.Length:
                    roots.Add(args[++i].Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant());
                    break;
                case "--userid" when i + 1 < args.Length:
                    userId = args[++i];
                    break;
                case "--time" when i + 1 < args.Length:
                    if (!DateTimeOffset.TryParse(args[++i], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out at))
                    {
                        error.WriteLine("onecrypto pgp authenticate: --time is not a date and time.");
                        return 2;
                    }

                    break;
                default:
                    if (args[i].StartsWith("--", StringComparison.Ordinal))
                    {
                        error.WriteLine($"onecrypto pgp authenticate: unknown option '{args[i]}'.");
                        return 2;
                    }

                    files.Add(args[i]);
                    break;
            }
        }

        if (roots.Count == 0 || files.Count == 0)
        {
            error.WriteLine("usage: onecrypto pgp authenticate --root FINGERPRINT... [--userid TEXT] [--time ISO-8601] CERTIFICATE-FILE...");
            return 2;
        }

        var certs = new List<PgpCertificate>();
        try
        {
            foreach (string f in files)
            {
                byte[] bytes = File.ReadAllBytes(f);
                if (bytes.Length > 0 && Armor.LooksArmored(bytes[0]))
                {
                    bytes = Armor.Decode(bytes).Data;
                }

                certs.AddRange(PgpCertificate.ParseAll(bytes));
            }

            TrustNetwork net = TrustNetwork.Build(certs, at);
            bool all = true;
            foreach (PgpCertificate c in certs)
            {
                string id = Convert.ToHexString(c.Fingerprint);
                if (roots.Contains(id))
                {
                    continue;
                }

                foreach (string u in c.UserIds)
                {
                    if (userId is not null && !string.Equals(u, userId, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    FlowAuthentication r = WebOfTrust.Authenticate(net, roots, id, u);
                    all &= r.IsAuthenticated;
                    var line = new StringBuilder();
                    line.Append(CultureInfo.InvariantCulture, $"{id} \"{u}\": {r.Level} ({r.Amount} of {r.Required})");
                    output.WriteLine(line.ToString());
                    foreach (TrustPath p in r.Paths)
                    {
                        output.WriteLine($"  path, amount {p.Amount}: {string.Join(" -> ", p.Certifications.Select(x => x.Issuer[^16..]).Append(id[^16..]))}");
                    }

                    foreach (string reason in r.Reasons)
                    {
                        output.WriteLine($"  {reason}");
                    }
                }
            }

            return all ? 0 : 1;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or OpenPgpParseException or TrustLimitExceededException)
        {
            error.WriteLine($"onecrypto pgp authenticate: {e.Message}");
            return 2;
        }
    }
}
