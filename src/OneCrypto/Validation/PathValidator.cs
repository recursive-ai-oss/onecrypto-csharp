using System.Linq;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Validation;

/// <summary>
/// The library's RFC 5280 path builder and validator. The verdict depends only on the inputs and the reference time:
/// operating-system stores are at most a source of trust anchors (<see cref="OsTrustStore"/>), never an engine.
/// Bad input is a report, not an exception.
/// </summary>
public static class PathValidator
{
    /// <summary>
    /// Builds candidate paths from <paramref name="target"/> to a trust anchor and validates them (RFC 5280 §6.1, with revocation per §6.3 and RFC 6960
    /// from the data in <paramref name="options"/>). Nothing is fetched and no clock is read.
    /// </summary>
    /// <param name="target">The certificate to validate.</param>
    /// <param name="options">Anchors, intermediates, reference time, policy and limits.</param>
    /// <returns>The verdict and a report for every path tried. Never throws for malformed certificates or data.</returns>
    public static ValidationReport Validate(Certificate target, ValidationOptions options)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(options);
        return new Engine(options).Run(target);
    }

    /// <summary>
    /// Like <see cref="Validate"/>, and when <see cref="ValidationOptions.CertificateSource"/> or <see cref="ValidationOptions.RevocationSource"/> is set,
    /// asks it for missing issuers and revocation data and validates again, at most <see cref="ValidationLimits.MaxSourceRounds"/> times.
    /// Without a source this does no I/O.
    /// </summary>
    /// <param name="target">The certificate to validate.</param>
    /// <param name="options">The options, including the optional sources.</param>
    /// <param name="cancellationToken">Cancels the source calls.</param>
    public static async ValueTask<ValidationReport> ValidateAsync(Certificate target, ValidationOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(options);
        ValidationReport report = Validate(target, options);
        if (options.CertificateSource is null && options.RevocationSource is null)
        {
            return report;
        }

        var intermediates = new List<Certificate>(options.Intermediates);
        var crls = new List<CertificateRevocationList>(options.Revocation?.Crls ?? []);
        var ocsp = new List<OcspBasicResponse>(options.Revocation?.OcspResponses ?? []);
        for (int round = 0; round < options.Limits.MaxSourceRounds; round++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            bool changed = false;
            if (report.SelectedPath is null && options.CertificateSource is { } cs)
            {
                foreach (Certificate c in report.Unchained)
                {
                    var uris = report.IssuerLocations.Where(l => ReferenceEquals(l.Certificate, c)).Select(l => l.Uri).ToList();
                    foreach (Certificate found in await cs.FindIssuersAsync(c, uris, cancellationToken).ConfigureAwait(false))
                    {
                        if (found is not null && !intermediates.Any(x => x.Equals(found)))
                        {
                            intermediates.Add(found);
                            changed = true;
                        }
                    }
                }
            }
            else if (report.SelectedPath is { } sp && options.RevocationSource is { } rs && sp.Certificates.Any(c => c.Revocation.Status == RevocationStatus.Unknown))
            {
                for (int i = 0; i < sp.Certificates.Length; i++)
                {
                    CertificateReport cr = sp.Certificates[i];
                    if (cr.Revocation.Status != RevocationStatus.Unknown)
                    {
                        continue;
                    }

                    Certificate? issuer = i == 0 ? sp.AnchorCertificate : sp.Certificates[i - 1].Certificate;
                    if (issuer is null)
                    {
                        continue;
                    }

                    var view = new CertView(cr.Certificate);
                    List<string> crlUris = [.. view.CrlDistributionPoints?.Points.Select(p => p.Name?.FullName).Where(n => n is not null).SelectMany(n => n!).Where(n => n.Kind == GeneralNameKind.Uri).Select(n => n.Value!) ?? []];
                    List<string> ocspUris = [.. view.AuthorityInfoAccess?.UrisFor(KnownOids.AdOcsp) ?? []];
                    RevocationData more = await rs.GetRevocationDataAsync(cr.Certificate, issuer, crlUris, ocspUris, cancellationToken).ConfigureAwait(false);
                    foreach (CertificateRevocationList crl in more.Crls)
                    {
                        if (!crls.Any(x => x.Equals(crl)))
                        {
                            crls.Add(crl);
                            changed = true;
                        }
                    }

                    foreach (OcspBasicResponse o in more.OcspResponses)
                    {
                        if (!ocsp.Any(x => x.Equals(o)))
                        {
                            ocsp.Add(o);
                            changed = true;
                        }
                    }
                }
            }

            if (!changed)
            {
                break;
            }

            report = Validate(target, With(options, intermediates, new RevocationData { Crls = crls, OcspResponses = ocsp }));
        }

        return report;
    }

    /// <summary>Copies the options with another intermediate pool and revocation data (used by the CMS chain step and the fetch loop).</summary>
    internal static ValidationOptions With(ValidationOptions o, IReadOnlyList<Certificate> intermediates, RevocationData? revocation) => new()
    {
        TrustAnchors = o.TrustAnchors,
        Intermediates = intermediates,
        ReferenceTime = o.ReferenceTime,
        RevocationDataTime = o.RevocationDataTime,
        Revocation = revocation,
        RevocationRequired = o.RevocationRequired,
        UnknownRevocationIsFatal = o.UnknownRevocationIsFatal,
        RevocationModel = o.RevocationModel,
        OcspMaxAge = o.OcspMaxAge,
        Policy = o.Policy,
        RequiredExtendedKeyUsage = o.RequiredExtendedKeyUsage,
        RequiredKeyUsage = o.RequiredKeyUsage,
        InitialPolicySet = o.InitialPolicySet,
        InitialExplicitPolicy = o.InitialExplicitPolicy,
        InitialPolicyMappingInhibit = o.InitialPolicyMappingInhibit,
        InitialAnyPolicyInhibit = o.InitialAnyPolicyInhibit,
        ApplyAnchorNameConstraints = o.ApplyAnchorNameConstraints,
        StrictAnchorStructure = o.StrictAnchorStructure,
        ApplyAnchorPolicyConstraints = o.ApplyAnchorPolicyConstraints,
        CheckAnchorValidity = o.CheckAnchorValidity,
        MaxIntermediates = o.MaxIntermediates,
        StrictStructure = o.StrictStructure,
        WebPki = o.WebPki,
        Limits = o.Limits,
        CertificateSource = o.CertificateSource,
        RevocationSource = o.RevocationSource,
        TrustedOcspResponders = o.TrustedOcspResponders,
    };
}

/// <summary>A read-only loader of the operating system's root certificates, to use as trust anchors. The validation itself never consults the platform.</summary>
public static class OsTrustStore
{
    /// <summary>
    /// The certificates in the current user's and the machine's Root stores that the library can read, as anchors. Empty where the platform has no store
    /// (the browser). On Windows this reads the Root stores through the same call; the code path is untested there.
    /// </summary>
    public static IReadOnlyList<TrustAnchor> LoadRoots()
    {
        var anchors = new List<TrustAnchor>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (StoreLocation loc in new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser })
        {
            try
            {
                using var store = new X509Store(StoreName.Root, loc);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                foreach (X509Certificate2 c in store.Certificates)
                {
                    try
                    {
                        Certificate cert = Certificate.FromX509Certificate2(c);
                        if (seen.Add(Convert.ToHexString(cert.ComputeFingerprint(System.Security.Cryptography.HashAlgorithmName.SHA256))))
                        {
                            anchors.Add(TrustAnchor.FromCertificate(cert));
                        }
                    }
                    catch (X509ParseException)
                    {
                        // A certificate the library cannot read is not offered as an anchor.
                    }
                    finally
                    {
                        c.Dispose();
                    }
                }
            }
            catch (CryptographicException)
            {
                // No such store on this platform.
            }
            catch (PlatformNotSupportedException)
            {
                // The browser has no certificate store.
            }
        }

        return anchors;
    }
}

/// <summary>The result of comparing our verdict with the platform's <see cref="X509Chain"/> on the same inputs.</summary>
/// <param name="OurVerdict">Our verdict.</param>
/// <param name="PlatformBuilt">Whether <see cref="X509Chain.Build"/> returned true.</param>
/// <param name="PlatformStatus">The platform's chain status flags, as text.</param>
/// <param name="Agrees">Whether both say valid or both say not valid.</param>
/// <param name="Note">A sentence describing a disagreement, empty when they agree.</param>
public sealed record ChainDiagnostic(ValidationVerdict OurVerdict, bool PlatformBuilt, string PlatformStatus, bool Agrees, string Note);

/// <summary>An opt-in side-by-side with the platform's chain engine. It is informational and never part of a verdict.</summary>
public static class ChainDiagnostics
{
    /// <summary>
    /// Runs <see cref="X509Chain"/> offline (no revocation, the anchors as custom roots, the intermediates as extra certificates, the reference time as verification time)
    /// and compares the outcome with <paramref name="report"/>.
    /// </summary>
    /// <param name="target">The certificate that was validated.</param>
    /// <param name="options">The options it was validated with.</param>
    /// <param name="report">Our report for those inputs.</param>
    public static ChainDiagnostic Compare(Certificate target, ValidationOptions options, ValidationReport report)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(report);
        try
        {
            using X509Certificate2 leaf = target.ToX509Certificate2();
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationTime = options.ReferenceTime.UtcDateTime;
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            foreach (TrustAnchor a in options.TrustAnchors)
            {
                if (a.Certificate is not null && a.Certificate.TryToX509Certificate2(out X509Certificate2? x509))
                {
                    chain.ChainPolicy.CustomTrustStore.Add(x509!);
                }
            }

            foreach (Certificate c in options.Intermediates)
            {
                if (c.TryToX509Certificate2(out X509Certificate2? x509))
                {
                    chain.ChainPolicy.ExtraStore.Add(x509!);
                }
            }

            bool built = chain.Build(leaf);
            string status = string.Join(", ", chain.ChainStatus.Select(s => s.Status.ToString()));
            bool agree = built == report.IsValid;
            string note = agree ? string.Empty : report.IsValid
                ? $"we accept the path, the platform does not ({status})"
                : $"the platform accepts the chain, we do not ({report.DecidingRule})";
            return new ChainDiagnostic(report.Verdict, built, status, agree, note);
        }
        catch (CryptographicException e)
        {
            return new ChainDiagnostic(report.Verdict, false, "platform error: " + e.Message, false, "the platform could not load the certificate");
        }
        catch (PlatformNotSupportedException e)
        {
            return new ChainDiagnostic(report.Verdict, false, "platform error: " + e.Message, false, "this platform has no chain engine");
        }
    }
}
