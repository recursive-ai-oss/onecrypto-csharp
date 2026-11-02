using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.Online.Csc;
using RecursiveAI.OneCrypto.Validation;

namespace OneCrypto.Smoke;

/// <summary>
/// One replayed fetch in an app that is trimmed, AOT-compiled or run in the browser: a recorded exchange written to and read back from its JSON file format, served
/// by the replay transport through the fetcher's guards and cache, then used, through the validator's issuer source, to complete a certificate chain. No socket is
/// opened; the guard refuses a private address and the cache serves the second request without a second exchange.
/// </summary>
internal static class OnlineSmoke
{
    public static async Task<bool> Run()
    {
        var log = new ExchangeLog();
        log.Exchanges.Add(new RecordedExchange
        {
            Method = "GET",
            Uri = "http://pki.smoke.test/ca.crt",
            Status = 200,
            Headers = [new RecordedHeader { Name = "Content-Type", Value = "application/pkix-cert" }, new RecordedHeader { Name = "Cache-Control", Value = "max-age=3600" }],
            Body = Convert.FromBase64String(ValidationSmoke.Ca),
        });
        ExchangeLog reread = ExchangeLog.Parse(log.ToJson());
        var replay = new ReplayTransport(reread);
        var fetcher = new Fetcher(replay, new FetchOptions());

        var issuers = new OnlineCertificateSource(fetcher);
        var leaf = Certificate.Parse(Convert.FromBase64String(ValidationSmoke.Leaf));
        IReadOnlyList<Certificate> found = await issuers.FindIssuersAsync(leaf, ["http://pki.smoke.test/ca.crt"], CancellationToken.None);
        IReadOnlyList<Certificate> again = await issuers.FindIssuersAsync(leaf, ["http://pki.smoke.test/ca.crt"], CancellationToken.None);

        ValidationReport report = PathValidator.Validate(leaf, new ValidationOptions
        {
            TrustAnchors = [TrustAnchor.FromCertificate(Certificate.Parse(Convert.FromBase64String(ValidationSmoke.Root)))],
            Intermediates = found,
            ReferenceTime = new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
        });

        FetchResult blocked = await fetcher.FetchAsync(new FetchRequest { Uri = new Uri("http://10.0.0.1/ca.crt"), Origin = UrlOrigin.Certificate });

        // The remote-signing client reads its JSON without reflection: one replayed info call.
        var cscLog = new ExchangeLog();
        cscLog.Exchanges.Add(new RecordedExchange
        {
            Method = "POST",
            Uri = "https://csc.smoke.test/v2/info",
            Status = 200,
            Headers = [new RecordedHeader { Name = "Content-Type", Value = "application/json" }],
            Body = System.Text.Encoding.UTF8.GetBytes("{\"specs\":\"2.2.0.0\",\"name\":\"smoke\",\"authType\":[\"oauth2client\"],\"methods\":[\"signatures/signHash\"]}"),
        });
        var csc = new CscClient(new Fetcher(new ReplayTransport(cscLog, new ReplayOptions { MatchBody = false })), new Uri("https://csc.smoke.test/v2/"));
        CscResult<CscServiceInfo> cscInfo = await csc.InfoAsync();
        bool cscGood = cscInfo.IsSuccess && cscInfo.Value!.Specs == "2.2.0.0" && cscInfo.Value.SupportsMethod("signatures/signHash") && !cscInfo.Value.SupportsMethod("credentials/list");

        bool good = cscGood && found.Count == 1 && again.Count == 1 && replay.Requests.Count == 1 && report.IsValid && blocked.Outcome == FetchOutcome.AddressBlocked;
        Console.WriteLine($"online: replayed {replay.Requests.Count} request(s), issuer found {found.Count}, validation {report.Verdict}, private address {blocked.Outcome}, csc info {cscInfo.Outcome}");
        return good;
    }
}
