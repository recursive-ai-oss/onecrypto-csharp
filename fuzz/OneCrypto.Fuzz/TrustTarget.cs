using System.Linq;
using System.Runtime.CompilerServices;
using RecursiveAI.OneCrypto.OpenPgp;
using RecursiveAI.OneCrypto.OpenPgp.GnuPG;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.OpenPgp.Trust;

namespace OneCrypto.Fuzz;

/// <summary>
/// The trust computations. Input: a mode byte, a root-count byte, an owner-trust byte, then a bundle of OpenPGP certificates. The first
/// certificates (as many as the root-count byte says, at least one) are the roots, the last is the target. The bundle goes through the
/// network builder, then the flow model and the classic model under small limits. Only <see cref="OpenPgpParseException"/> and
/// <see cref="TrustLimitExceededException"/> may come out.
/// </summary>
internal static class TrustTarget
{
    private static readonly TrustLimits Small = new()
    {
        MaxCertificates = 64,
        MaxCertifications = 4096,
        MaxRoots = 16,
        MaxWork = 2_000_000,
        MaxRegexLength = 256,
        MaxRegexStates = 512,
    };

    private static readonly DateTimeOffset At = new(2025, 6, 1, 0, 0, 0, TimeSpan.Zero);

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4)
        {
            return;
        }

        byte mode = data[0];
        int rootCount = 1 + (data[1] % 4);
        byte ownerBits = data[2];
        byte[] bundle = data[3..].ToArray();
        try
        {
            IReadOnlyList<PgpCertificate> certs = PgpCertificate.ParseAll(bundle);
            if (certs.Count == 0)
            {
                return;
            }

            TrustNetwork net = TrustNetwork.Build(certs, At, limits: Small);
            string[] roots = certs.Take(rootCount).Select(c => Convert.ToHexString(c.Fingerprint)).ToArray();
            PgpCertificate target = certs[^1];
            string? userId = target.UserIds.FirstOrDefault();
            if ((mode & 1) == 0 && userId is not null)
            {
                FlowAuthentication a = WebOfTrust.Authenticate(net, roots, Convert.ToHexString(target.Fingerprint), userId, limits: Small, stopAtRequired: (mode & 2) != 0);
                if (a.Amount < 0 || a.Paths.Any(p => p.Amount <= 0))
                {
                    throw new InvalidOperationException("A path with no trust amount was reported.");
                }
            }

            if ((mode & 1) == 1)
            {
                var owner = new Dictionary<string, OwnerTrustLevel>(StringComparer.Ordinal);
                for (int i = 0; i < certs.Count; i++)
                {
                    owner[Convert.ToHexString(certs[i].Fingerprint)] = ((ownerBits >> (i % 4 * 2)) & 3) switch { 0 => OwnerTrustLevel.Undefined, 1 => OwnerTrustLevel.Never, 2 => OwnerTrustLevel.Marginal, _ => OwnerTrustLevel.Full };
                }

                owner[roots[0]] = OwnerTrustLevel.Ultimate;
                ClassicTrustReport report = ClassicTrust.Evaluate(net, owner, new ClassicTrustOptions { MaxCertDepth = 1 + (mode >> 2) % 6 }, Small);
                foreach (CertificateValidity v in report.Certificates.Values)
                {
                    _ = v.UserIds.Count;
                }
            }
        }
        catch (OpenPgpParseException)
        {
        }
        catch (TrustLimitExceededException)
        {
        }
    }

    public static IEnumerable<byte[]> Seeds()
    {
        string dir = Path.Combine(Path.GetDirectoryName(ThisFile())!, "..", "..", "testdata", "openpgp", "trust");
        if (!Directory.Exists(dir))
        {
            yield break;
        }

        int n = 0;
        foreach (string file in Directory.GetFiles(dir, "certs.pgp", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            byte[] bytes = File.ReadAllBytes(file);
            if (bytes.Length > 60_000 || n++ % 3 != 0)
            {
                continue;
            }

            yield return [0, 0, 0xE4, .. bytes];
            yield return [1, 0, 0xE4, .. bytes];
        }
    }

    private static string ThisFile([CallerFilePath] string path = "") => path;
}
