using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.Tsp;
using RecursiveAI.OneCrypto.Validation;
using RevocationStatus = RecursiveAI.OneCrypto.Validation.RevocationStatus;

namespace OneCrypto.Online.Tests;

/// <summary>
/// Real public endpoints, replayed from exchanges recorded in <c>testdata/online</c>. The same tests run live when <c>ONECRYPTO_ONLINE_LIVE=1</c> (never in CI);
/// with <c>ONECRYPTO_ONLINE_RECORD=&lt;directory&gt;</c> as well they write fresh recordings there.
/// </summary>
public class PublicEndpointTests
{
    private static readonly byte[] FixedNonce = [0x4F, 0x6E, 0x65, 0x43, 0x72, 0x79, 0x70, 0x74];
    private static readonly byte[] Document = "OneCrypto online fixture"u8.ToArray();

    internal static readonly (string Name, string Url)[] Authorities =
    [
        ("freetsa", "https://freetsa.org/tsr"),
        ("digicert", "http://timestamp.digicert.com"),
        ("sectigo", "http://timestamp.sectigo.com"),
        ("globalsign", "http://timestamp.globalsign.com/tsa/r6advanced1"),
    ];

    private static string Data(string file) => Path.Combine(TestFiles.TestData, "online", file);

    private static bool Live => Environment.GetEnvironmentVariable("ONECRYPTO_ONLINE_LIVE") == "1";

    private static string? RecordDir => Environment.GetEnvironmentVariable("ONECRYPTO_ONLINE_RECORD");

    public static IEnumerable<TheoryDataRow<string>> AuthorityNames() => Authorities.Select(a => new TheoryDataRow<string>(a.Name));

    private static async Task<ValidationReport> ValidateGlobalSign(ITransport transport, DateTimeOffset at, List<OnlineAttempt> attempts)
    {
        Certificate leaf = Certificate.FromPem(File.ReadAllText(Data("globalsign-leaf.pem")));
        Certificate root = Certificate.FromPem(File.ReadAllText(Data("globalsign-root-r46.pem")));
        var fetcher = new Fetcher(transport, new FetchOptions { Cache = null });
        var revocation = new OnlineRevocationSource(fetcher, new OnlineRevocationOptions { ReferenceTime = at, Preference = RevocationPreference.Both });
        var issuers = new OnlineCertificateSource(fetcher);
        ValidationReport report = await PathValidator.ValidateAsync(leaf, new ValidationOptions
        {
            TrustAnchors = [TrustAnchor.FromCertificate(root)],
            ReferenceTime = at,
            RevocationRequired = RevocationScope.AllCertificates,
            CertificateSource = issuers,
            RevocationSource = revocation,
        });
        attempts.AddRange(issuers.Attempts);
        attempts.AddRange(revocation.Attempts);
        return report;
    }

    [Fact]
    public async Task ARealChainValidatesWithOcspAndCrlFromRecordedExchanges()
    {
        ExchangeLog log = ExchangeLog.Parse(File.ReadAllBytes(Data("globalsign-chain.exchanges.json")));
        DateTimeOffset at = log.Exchanges.Max(e => e.RecordedAt!.Value);
        var replay = new ReplayTransport(log);
        var attempts = new List<OnlineAttempt>();
        ValidationReport r = await ValidateGlobalSign(replay, at, attempts);
        Assert.True(r.IsValid, r.ToString());
        Assert.Equal(RevocationStatus.Good, r.RevocationSummary);
        Assert.Equal(2, r.SelectedPath!.Certificates.Length);
        Assert.Contains(attempts, a => a.Kind == "aia" && a.Succeeded);
        Assert.Contains(attempts, a => a.Kind == "ocsp" && a.Succeeded);
        Assert.Contains(attempts, a => a.Kind == "crl" && a.Succeeded);
        Assert.DoesNotContain(replay.Requests, q => !log.Exchanges.Any(e => q.EndsWith(e.Uri, StringComparison.Ordinal)));

        // The same data one year later: the CRLs and OCSP answers have lapsed, so nothing vouches for the certificates any more.
        var late = new List<OnlineAttempt>();
        ValidationReport stale = await ValidateGlobalSign(new ReplayTransport(log), at.AddDays(200), late);
        Assert.False(stale.IsValid);
    }

    [Theory]
    [MemberData(nameof(AuthorityNames))]
    public async Task ARecordedPublicTimestampVerifiesAgainstItsRequest(string name)
    {
        ExchangeLog log = ExchangeLog.Parse(File.ReadAllBytes(Data($"tsa-{name}.exchanges.json")));
        string url = Authorities.Single(a => a.Name == name).Url;
        TimestampResult r = await Stamp(new ReplayTransport(log), url);
        Assert.True(r.IsGranted, r.Reason);
        Assert.NotNull(r.Report!.GenTime);
        Assert.True(r.Report.GenTime > new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        Assert.False(r.Token.IsEmpty);
    }

    private static async Task<TimestampResult> Stamp(ITransport transport, string url)
    {
        var client = new TsaClient(new Fetcher(transport, new FetchOptions { Cache = null }));
        return await client.StampAsync(new Uri(url), Document, HashAlgorithmName.SHA256, new TimestampRequestOptions { Nonce = FixedNonce });
    }

    [Fact]
    public async Task LiveChainValidationAgainstGlobalSign()
    {
        Assert.SkipUnless(Live, "set ONECRYPTO_ONLINE_LIVE=1 to talk to the public endpoints");
        ITransport t = new HttpTransport();
        RecordingTransport? rec = RecordDir is null ? null : new RecordingTransport(t);
        var attempts = new List<OnlineAttempt>();
        ValidationReport r = await ValidateGlobalSign(rec ?? t, DateTimeOffset.UtcNow, attempts);
        if (rec is not null)
        {
            Directory.CreateDirectory(RecordDir!);
            await File.WriteAllBytesAsync(Path.Combine(RecordDir!, "globalsign-chain.exchanges.json"), rec.Log.ToJson());
        }

        Console.WriteLine($"live chain: {r.Verdict}, revocation {r.RevocationSummary}; " + string.Join("; ", attempts.Select(a => $"{a.Kind} {a.Uri} {(a.Succeeded ? "ok" : "FAILED")} {a.Detail}")));
        Assert.True(r.IsValid, r + " " + string.Join("; ", attempts.Where(a => !a.Succeeded).Select(a => a.Detail)));
        Assert.Equal(RevocationStatus.Good, r.RevocationSummary);
    }

    [Theory]
    [MemberData(nameof(AuthorityNames))]
    public async Task LiveTimestampFromAPublicAuthority(string name)
    {
        Assert.SkipUnless(Live, "set ONECRYPTO_ONLINE_LIVE=1 to talk to the public endpoints");
        string url = Authorities.Single(a => a.Name == name).Url;
        ITransport t = new HttpTransport();
        RecordingTransport? rec = RecordDir is null ? null : new RecordingTransport(t);
        TimestampResult r = await Stamp(rec ?? t, url);
        if (rec is not null)
        {
            Directory.CreateDirectory(RecordDir!);
            await File.WriteAllBytesAsync(Path.Combine(RecordDir!, $"tsa-{name}.exchanges.json"), rec.Log.ToJson());
        }

        Console.WriteLine($"live tsa {name}: {r.Outcome} {r.Reason} genTime {r.Report?.GenTime?.ToString("u", CultureInfo.InvariantCulture)} contentType {r.Fetch.ContentType}");
        Assert.True(r.IsGranted, r.Reason);
        _ = Encoding.ASCII;
    }
}
