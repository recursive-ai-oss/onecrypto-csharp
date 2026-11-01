using System.Linq;
using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Issuance;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.Tsp;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Fuzz;

/// <summary>
/// The HTTP response handling of the online clients as one fuzz target (<c>online</c>). The input is an HTTP response as the fetcher meets it: a status code, a
/// way of declaring or lying about the length, a header block, a body that may be cut short or fail mid-read. Byte 0 picks the consumer: the fetcher itself (with
/// its cache and redirect handling), or the time-stamp, OCSP, CRL or issuer-certificate interpretation of what the fetcher returned, or the small parsers
/// (Cache-Control, HTTP dates, recorded exchange files). Nothing may throw: a hostile server gets a typed result.
/// </summary>
internal static class OnlineTarget
{
    private static readonly Lazy<Rig> Shared = new(() => new Rig());

    private static readonly int[] Statuses = [200, 200, 200, 204, 301, 302, 303, 304, 307, 308, 400, 404, 500, 503, 100, 999];

    private sealed class Rig
    {
        public readonly TimeStampRequest TsaRequest;
        public readonly OcspRequest OcspRequest;
        public readonly OcspCertId CertId;
        public readonly byte[] TsaReply, OcspReply, Crl, Cert;

        public Rig()
        {
            DateTimeOffset now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
            var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            CertificateAuthority ca = CertificateAuthority.CreateRoot(DistinguishedName.Create((KnownOids.CommonName, "Fuzz CA")), X509Signer.FromECDsa(caKey), now.AddDays(-30), TimeSpan.FromDays(3650));
            var tsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            Certificate tsa = ca.Issue(PublicKeyInfo.FromAsymmetricAlgorithm(tsaKey), DistinguishedName.Create((KnownOids.CommonName, "Fuzz TSA")), new CertificateIssueOptions { Profile = CertificateProfile.TimeStamping, NotBefore = now.AddDays(-1) });
            var authority = new TimeStampAuthority(new TimeStampAuthorityOptions { Certificate = tsa, Signer = X509Signer.FromECDsa(tsaKey), DefaultPolicy = "1.2.3.4.1" }, new CounterTimeStampSerialSource());
            TsaRequest = TimeStampRequest.Create(new TimeStampRequestOptions { Hash = HashAlgorithmName.SHA256, MessageImprint = SHA256.HashData("fuzz"u8), Nonce = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 } });
            TsaReply = authority.Handle(TsaRequest.Encoded, now).Encoded.ToArray();

            var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            Cert = ca.Issue(PublicKeyInfo.FromAsymmetricAlgorithm(leafKey), DistinguishedName.Create((KnownOids.CommonName, "Fuzz leaf")), new CertificateIssueOptions { Profile = CertificateProfile.CodeSigning, NotBefore = now.AddDays(-1) }).Encoded.ToArray();
            Certificate leaf = Certificate.Parse(Cert);
            var source = new InMemoryRevocationSource(TimeSpan.FromHours(1));
            source.SetGood(leaf.SerialNumber.Span);
            var responder = new OcspResponder(new OcspResponderOptions { Issuer = ca.Certificate, ResponderCertificate = ca.Certificate, Signer = X509Signer.FromECDsa(caKey), Source = source });
            CertId = OcspCertId.Create(leaf, ca.Certificate);
            OcspRequest = OcspRequestBuilder.Create(new OcspRequestOptions { Requests = [CertId], Nonce = new byte[] { 9, 8, 7, 6 } });
            OcspReply = responder.Handle(OcspRequest.Encoded, now).Encoded.ToArray();
            Crl = ca.IssueCrl(new CrlIssueOptions { ThisUpdate = now, NextUpdate = now.AddDays(7), Number = 1 }).Encoded.ToArray();
        }
    }

    /// <summary>The first four bytes describe the response; the rest of the input is the header block (length in byte 3) and then the body.</summary>
    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4)
        {
            return;
        }

        int surface = data[0] % 6;
        int status = Statuses[data[1] % Statuses.Length];
        byte flags = data[2];
        int headerLength = Math.Min(data[3], data.Length - 4);
        string headerText = Encoding.Latin1.GetString(data.Slice(4, headerLength));
        byte[] body = data[(4 + headerLength)..].ToArray();

        if (surface == 5)
        {
            SmallParsers(headerText, body);
            return;
        }

        var headers = new List<KeyValuePair<string, string>>();
        foreach (string line in headerText.Split('\n'))
        {
            int i = line.IndexOf(':', StringComparison.Ordinal);
            if (i > 0)
            {
                headers.Add(new KeyValuePair<string, string>(line[..i].Trim(), line[(i + 1)..].Trim()));
            }
        }

        if ((flags & 1) != 0)
        {
            headers.Add(new("Content-Length", body.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }

        if ((flags & 2) != 0)
        {
            headers.Add(new("Content-Length", (body.Length + 1 + (flags >> 3)).ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }

        bool failMidway = (flags & 4) != 0;
        int calls = 0;
        var net = new Network(request =>
        {
            calls++;
            Stream s = failMidway && calls > 1 ? new FailingStream(body) : new MemoryStream(body, writable: false);
            return new TransportResponse(status, headers, s);
        });
        var fetcher = new Fetcher(net, new FetchOptions
        {
            MaxResponseBytes = 8192,
            Timeout = TimeSpan.FromSeconds(2),
            Cache = new MemoryFetchCache(1 << 20, 16),
            MaxRedirects = 2,
        });

        var uri = new Uri("http://example.test/resource");
        UrlOrigin origin = (flags & 0x80) != 0 ? UrlOrigin.Certificate : UrlOrigin.Caller;
        Rig rig = Shared.Value;
        switch (surface)
        {
            case 0:
                Fetch(fetcher, uri, origin, FetchCacheMode.Http, "GET");
                Fetch(fetcher, uri, origin, FetchCacheMode.Http, "GET");
                Fetch(fetcher, uri, origin, FetchCacheMode.Content, "POST");
                break;
            case 1:
                _ = TsaClient.Interpret(rig.TsaRequest, Fetch(fetcher, uri, origin, FetchCacheMode.None, "POST"));
                break;
            case 2:
                _ = OcspClient.Interpret(rig.OcspRequest, rig.CertId, Fetch(fetcher, uri, origin, FetchCacheMode.None, "POST"));
                break;
            case 3:
                _ = CrlClient.Interpret(uri, Fetch(fetcher, uri, origin, FetchCacheMode.Http, "GET"), new DateTimeOffset(2026, 6, 2, 0, 0, 0, TimeSpan.Zero));
                break;
            default:
                _ = AiaClient.Interpret(uri, Fetch(fetcher, uri, origin, FetchCacheMode.Http, "GET"));
                break;
        }
    }

    private static FetchResult Fetch(Fetcher f, Uri uri, UrlOrigin origin, FetchCacheMode cache, string method) =>
        f.FetchAsync(new FetchRequest { Uri = uri, Origin = origin, Cache = cache, Method = method, Body = method == "POST" ? new byte[] { 1, 2, 3 } : default, ServeStaleOnError = true, IsReusable = static b => b.Length > 3 }).AsTask().GetAwaiter().GetResult();

    private static void SmallParsers(string text, byte[] body)
    {
        CacheControl cc = CacheControl.Parse(text);
        _ = cc.MaxAge;
        _ = cc.NoStore;
        _ = cc.NoCache;
        _ = cc.MustRevalidate;
        _ = cc.Has("max-age");
        _ = CrlClient.TryParse(body, out _);
        _ = AiaClient.Interpret(new Uri("http://example.test/"), Ok(body));
        try
        {
            _ = ExchangeLog.Parse(body);
        }
        catch (FormatException)
        {
            // The documented failure of a file that is not a log.
        }

        var net = new Network(_ => new TransportResponse(200, [new("Date", text), new("Cache-Control", text), new("Age", text), new("Expires", text), new("Last-Modified", text), new("ETag", text)], new MemoryStream(body)));
        var f = new Fetcher(net, new FetchOptions { Cache = new MemoryFetchCache() });
        for (int i = 0; i < 2; i++)
        {
            _ = f.FetchAsync(new FetchRequest { Uri = new Uri("http://example.test/p"), Cache = FetchCacheMode.Http }).AsTask().GetAwaiter().GetResult();
        }
    }

    private static FetchResult Ok(byte[] body) =>
        new Fetcher(new Network(_ => new TransportResponse(200, [], new MemoryStream(body))), new FetchOptions { Cache = null }).FetchAsync(new FetchRequest { Uri = new Uri("http://example.test/") }).AsTask().GetAwaiter().GetResult();

    public static IEnumerable<byte[]> Seeds()
    {
        Rig rig = Shared.Value;
        byte[] Make(byte surface, byte status, byte flags, string headers, byte[] body) =>
            [surface, status, flags, (byte)headers.Length, .. Encoding.Latin1.GetBytes(headers), .. body];
        yield return Make(0, 0, 1, "Cache-Control: max-age=60\nETag: \"x\"", rig.Crl);
        yield return Make(0, 5, 0, "Location: /elsewhere", []);
        yield return Make(0, 7, 0, "Cache-Control: max-age=0", []);
        yield return Make(1, 0, 1, "Content-Type: application/timestamp-reply", rig.TsaReply);
        yield return Make(2, 0, 1, "Content-Type: application/ocsp-response", rig.OcspReply);
        yield return Make(3, 0, 0, "Content-Type: application/pkix-crl\nCache-Control: public, max-age=3600", rig.Crl);
        yield return Make(4, 0, 0x80, "Content-Type: application/pkix-cert", rig.Cert);
        yield return Make(4, 0, 0, "", Encoding.ASCII.GetBytes("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"));
        yield return Make(5, 0, 0, "max-age=60, no-cache=\"x\", private", Encoding.ASCII.GetBytes("{\"version\":1,\"exchanges\":[]}"));
        yield return Make(5, 0, 0, "Sun, 06 Nov 1994 08:49:37 GMT", []);
        yield return Make(1, 12, 3, "Content-Length: 99999999999", rig.TsaReply);
    }

    private sealed class Network : ITransport
    {
        private readonly Func<TransportRequest, TransportResponse> _make;

        public Network(Func<TransportRequest, TransportResponse> make) => _make = make;

        public ValueTask<TransportResponse> SendAsync(TransportRequest request, CancellationToken cancellationToken) => ValueTask.FromResult(_make(request));
    }

    /// <summary>A body that breaks after its first bytes, like a connection reset.</summary>
    private sealed class FailingStream : Stream
    {
        private readonly byte[] _data;
        private int _pos;

        public FailingStream(byte[] data) => _data = data;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_pos >= _data.Length / 2)
            {
                throw new IOException("connection reset");
            }

            int n = Math.Min(buffer.Length, _data.Length / 2 - _pos);
            _data.AsMemory(_pos, n).CopyTo(buffer);
            _pos += n;
            return ValueTask.FromResult(n);
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
