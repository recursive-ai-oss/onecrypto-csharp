using System.Text;
using RecursiveAI.OneCrypto.Validation;

namespace OneCrypto.Tests.Validation;

/// <summary>Plain-text rendering of a validation report, for failing assertions and debugging.</summary>
internal static class ReportText
{
    public static string Describe(ValidationReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"verdict {r.Verdict}, deciding: {r.DecidingRule}, limit: {r.LimitReached}, paths: {r.Paths.Length}, rejected: {r.Rejected.Length}");
        foreach (RuleResult t in r.TargetResults)
        {
            sb.AppendLine("  target: " + t);
        }

        foreach (RejectedCandidate c in r.Rejected)
        {
            sb.AppendLine($"  rejected {c.Candidate.Subject}: {c.Reason}");
        }

        int p = 0;
        foreach (PathReport path in r.Paths)
        {
            sb.AppendLine($" path {p++}: {path.Verdict} anchor {path.AnchorName}");
            foreach (RuleResult x in path.PathResults)
            {
                sb.AppendLine("    path: " + x);
            }

            foreach (CertificateReport c in path.Certificates)
            {
                sb.AppendLine($"   [{c.Index}] {c.Certificate.Subject} (revocation {c.Revocation.Status}: {c.Revocation.Reason})");
                foreach (RuleResult x in c.Results.Where(x => x.Outcome != RuleOutcome.Pass))
                {
                    sb.AppendLine("      " + x);
                }
            }
        }

        return sb.ToString();
    }
}
