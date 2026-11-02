using RecursiveAI.OneCrypto.OpenPgp.GnuPG;
using RecursiveAI.OneCrypto.OpenPgp.Trust;

namespace OneCrypto.Smoke;

/// <summary>Both trust models on a three-certificate network described by hand, and the regular-expression matcher.</summary>
internal static class TrustSmoke
{
    public static bool Run()
    {
        var at = new DateTimeOffset(2025, 6, 1, 0, 0, 0, TimeSpan.Zero);
        TrustNetwork net = TrustNetwork.FromEdges(
            ["a", "b", "c"],
            [new TrustCertification("a", "b", "B <b@example.org>", depth: 1), new TrustCertification("b", "c", "C <c@example.org>"), new TrustCertification("b", "b", "B <b@example.org>")],
            at);
        FlowAuthentication flow = WebOfTrust.Authenticate(net, ["a"], "c", "C <c@example.org>");
        if (!flow.IsAuthenticated || flow.Amount != 120 || flow.Paths.Count != 1)
        {
            return false;
        }

        FlowAuthentication none = WebOfTrust.Authenticate(net, ["c"], "a", "A <a@example.org>");
        if (none.IsAuthenticated)
        {
            return false;
        }

        var owner = new Dictionary<string, OwnerTrustLevel> { ["a"] = OwnerTrustLevel.Ultimate };
        ClassicTrustReport report = ClassicTrust.Evaluate(net, owner);
        if (report.ValidityOf("b", "B <b@example.org>") != ClassicValidity.Full)
        {
            return false;
        }

        return TrustRegex.TryCompile("<[^>]+[@.]example\\.org>$", out TrustRegex? re) && re!.IsMatch("X <x@example.org>") && !re.IsMatch("X <x@example.com>");
    }
}
