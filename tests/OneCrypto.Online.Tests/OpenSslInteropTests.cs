using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Issuance;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.Tsp;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;
using RevocationStatus = RecursiveAI.OneCrypto.Validation.RevocationStatus;

namespace OneCrypto.Online.Tests;

/// <summary>Our clients against OpenSSL's responders and OpenSSL's clients against our handlers, over real HTTP on the loopback interface. The openssl binary is a black box.</summary>
public class OpenSslInteropTests
{
    private static World W => World.Get();

    private static string Dir(string name) => IssuanceKit.Dir("online-" + name + "-" + Guid.NewGuid().ToString("N")[..6]);

    /// <summary>A long-running openssl process (<c>ocsp -port</c>) that is killed on dispose.</summary>
    private sealed class OpenSslProcess : IDisposable
    {
        private readonly Process _process;

        public OpenSslProcess(string dir, params string[] args)
        {
            string exe = Environment.GetEnvironmentVariable("ONECRYPTO_OPENSSL") is { Length: > 0 } e ? e : ToolRunner.Find("openssl")!;
            var psi = new ProcessStartInfo(exe) { RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = dir };
            if (Environment.GetEnvironmentVariable("ONECRYPTO_OPENSSL_LIB") is { Length: > 0 } lib)
            {
                psi.Environment["LD_LIBRARY_PATH"] = lib;
                psi.Environment["DYLD_LIBRARY_PATH"] = lib;
            }

            psi.Environment["OPENSSL_CONF"] = IssuanceKit.Write(dir, "empty.cnf", "[req]\ndistinguished_name = dn\n[dn]\n");
            foreach (string a in args)
            {
                psi.ArgumentList.Add(a);
            }

            _process = Process.Start(psi)!;
            _process.OutputDataReceived += (_, ev) => Append(ev.Data);
            _process.ErrorDataReceived += (_, ev) => Append(ev.Data);
            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();
        }

        private readonly StringBuilder _log = new();

        public string Log
        {
            get
            {
                lock (_log)
                {
                    return _log.ToString();
                }
            }
        }

        private void Append(string? line)
        {
            lock (_log)
            {
                _log.Append(line).Append('\n');
            }
        }

        public void Dispose()
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
            }

            _process.WaitForExit(3000);
            _process.Dispose();
        }
    }

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    /// <summary>openssl prints this when it is ready; connecting to probe the port would use up its single connection slot.</summary>
    private static async Task WaitListening(OpenSslProcess p)
    {
        for (int i = 0; i < 100; i++)
        {
            if (p.Log.Contains("waiting for OCSP client connections", StringComparison.Ordinal))
            {
                return;
            }

            await Task.Delay(50);
        }

        throw new TimeoutException("the openssl responder did not start: " + p.Log);
    }

    private static string IndexLine(Certificate c, bool revoked) =>
        revoked
            ? $"R\t301231000000Z\t{World.T0.AddMinutes(30).UtcDateTime:yyMMddHHmmss}Z,keyCompromise\t{Convert.ToHexString(c.SerialNumber.Span)}\tunknown\t/O=OneCrypto Online Tests/CN=revoked.test\n"
            : $"V\t301231000000Z\t\t{Convert.ToHexString(c.SerialNumber.Span)}\tunknown\t/O=OneCrypto Online Tests/CN=good.test\n";

    [Theory]
    [InlineData(OcspHttpMethod.Get, false)]
    [InlineData(OcspHttpMethod.Post, false)]
    [InlineData(OcspHttpMethod.Post, true)]
    public async Task OurClientQueriesOpenSslsResponder(OcspHttpMethod method, bool nonce)
    {
        OpenSslTool.RequireOrSkip();
        string dir = Dir("ocsp-a");
        IssuanceKit.Write(dir, "index.txt", IndexLine(W.Good, false) + IndexLine(W.Revoked, true));
        string ca = IssuanceKit.Write(dir, "ca.pem", W.Intermediate.Certificate.ToPem());
        string key = IssuanceKit.Write(dir, "ca.key", W.InterKey.ExportPkcs8PrivateKeyPem());
        int port = FreePort();
        using var responder = new OpenSslProcess(dir, "ocsp", "-index", Path.Combine(dir, "index.txt"), "-port", port.ToString(System.Globalization.CultureInfo.InvariantCulture), "-CA", ca, "-rsigner", ca, "-rkey", key, "-ndays", "1");
        await WaitListening(responder);

        using var transport = new HttpTransport();
        var client = new OcspClient(new Fetcher(transport, new FetchOptions { Cache = null }));
        var uri = new Uri($"http://127.0.0.1:{port}/");
        OcspQueryOptions Opts() => new() { ResponderUri = uri, Method = method, UseNonce = nonce, RequireNonce = nonce };

        OcspQueryResult good = await client.QueryAsync(W.Good, W.Intermediate.Certificate, Opts());
        Assert.True(good.Outcome == OcspOutcome.Answered, good.Reason + " " + responder.Log);
        Assert.Equal(OcspCertStatus.Good, good.Answer!.Status);
        Assert.Equal(nonce ? OcspNonceStatus.Matched : OcspNonceStatus.NotSent, good.Nonce);

        OcspQueryResult revoked = await client.QueryAsync(W.Revoked, W.Intermediate.Certificate, Opts());
        Assert.Equal(OcspCertStatus.Revoked, revoked.Answer!.Status);
        Assert.Equal(RevocationReason.KeyCompromise, revoked.Answer.RevocationReason);

        OcspQueryResult unknown = await client.QueryAsync(W.Unlisted, W.Intermediate.Certificate, Opts());
        Assert.Equal(OcspCertStatus.Unknown, unknown.Answer!.Status);

        // What came back is also acceptable to our validator: signed by the issuing CA, current now.
        ValidationReport report = Validate(W.Good, good.Basic!);
        Assert.True(report.IsValid, report.ToString() + " " + string.Join("; ", report.SelectedPath?.Certificates.Select(c => c.Revocation.Reason) ?? []));
        Assert.Equal(RevocationStatus.Good, report.SelectedPath!.Certificates[^1].Revocation.Status);
        Assert.Equal(ValidationVerdict.Invalid, Validate(W.Revoked, revoked.Basic!).Verdict);
    }

    private static ValidationReport Validate(Certificate leaf, OcspBasicResponse response) => PathValidator.Validate(leaf, new ValidationOptions
    {
        TrustAnchors = [TrustAnchor.FromCertificate(W.Root.Certificate)],
        Intermediates = [W.Intermediate.Certificate],
        ReferenceTime = World.Now,
        RevocationDataTime = DateTimeOffset.UtcNow,
        RevocationRequired = RevocationScope.EndEntity,
        Revocation = new RevocationData { OcspResponses = [response] },
    });

    [Theory]
    [InlineData("good", false)]
    [InlineData("good", true)]
    [InlineData("revoked", false)]
    public async Task OpenSslQueriesOurResponderOverHttp(string status, bool noNonce)
    {
        OpenSslTool.RequireOrSkip();
        string dir = Dir("ocsp-b");
        Certificate leaf = status == "good" ? W.Good : W.Revoked;
        string root = IssuanceKit.Write(dir, "root.pem", W.Root.Certificate.ToPem());
        string ca = IssuanceKit.Write(dir, "ca.pem", W.Intermediate.Certificate.ToPem());
        string leafFile = IssuanceKit.Write(dir, "leaf.pem", leaf.ToPem());
        using var server = new TestServer((line, _, body) =>
        {
            // POST carries the request in the body; a GET carries it in the path (RFC 6960 Appendix A.1).
            byte[] request = line.StartsWith("POST", StringComparison.Ordinal)
                ? body
                : Convert.FromBase64String(Uri.UnescapeDataString(line.Split(' ')[1][(line.Split(' ')[1].LastIndexOf('/') + 1)..]));
            return TestServer.Response(200, "OK", W.Responder.Handle(request, DateTimeOffset.UtcNow).Encoded.ToArray(), "Content-Type: application/ocsp-response");
        });

        var args = new List<string> { "ocsp", "-issuer", ca, "-cert", leafFile, "-url", $"http://127.0.0.1:{server.Port}/", "-CAfile", root, "-verify_other", ca };
        if (noNonce)
        {
            args.Add("-no_nonce");
        }

        (int code, string output) = await Task.Run(() => OpenSslTool.Run([.. args]));
        Assert.True(code == 0, "ocsp -url: " + output);
        Assert.Contains("Response verify OK", output, StringComparison.Ordinal);
        Assert.Contains($"leaf.pem: {status}", output, StringComparison.Ordinal);
        Assert.NotEmpty(server.RequestLines);
        if (status == "revoked")
        {
            Assert.Contains("Reason: keyCompromise", output, StringComparison.Ordinal);
        }
    }

    // ------------------------------------------------------------------ time-stamping

    private static Certificate TsaCertificateNow()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return W.Intermediate.Issue(PublicKeyInfo.FromAsymmetricAlgorithm(W.TsaKey), DistinguishedName.Create((KnownOids.CommonName, "Online Test TSA (current)")),
            new CertificateIssueOptions { Profile = CertificateProfile.TimeStamping, NotBefore = new DateTimeOffset(now.Year, now.Month, now.Day, 0, 0, 0, TimeSpan.Zero) });
    }

    [Theory]
    [InlineData("sha256", true)]
    [InlineData("sha384", true)]
    [InlineData("sha512", false)]
    public async Task OurClientStampsThroughAnOpenSslTimeStampAuthorityBehindAnHttpShim(string hash, bool certReq)
    {
        OpenSslTool.RequireOrSkip();
        string dir = Dir("ts-a");
        Certificate tsa = TsaCertificateNow();
        string conf = IssuanceKit.Write(dir, "ts.cnf", $$"""
            [ tsa ]
            default_tsa = tsa1
            [ tsa1 ]
            serial = {{dir}}/serial
            crypto_device = builtin
            signer_cert = {{IssuanceKit.Write(dir, "tsa.pem", tsa.ToPem())}}
            certs = {{IssuanceKit.Write(dir, "chain.pem", W.Intermediate.Certificate.ToPem())}}
            signer_key = {{IssuanceKit.Write(dir, "tsa.key", W.TsaKey.ExportPkcs8PrivateKeyPem())}}
            signer_digest = sha256
            default_policy = 1.2.3.4.1
            other_policies = 1.2.3.4.5
            digests = sha256, sha384, sha512
            accuracy = secs:1
            ordering = yes
            tsa_name = yes
            ess_cert_id_chain = no
            ess_cert_id_alg = sha256
            """);
        IssuanceKit.Write(dir, "serial", "0A\n");
        int n = 0;

        // The shim: the whole of RFC 3161 §3.4 is "POST the query, answer with the reply".
        using var shim = new TestServer((line, headers, body) =>
        {
            int i = Interlocked.Increment(ref n);
            string q = IssuanceKit.Write(dir, $"q{i}.tsq", body);
            string r = Path.Combine(dir, $"r{i}.tsr");
            (int code, string output) = OpenSslTool.Run("ts", "-reply", "-queryfile", q, "-config", conf, "-out", r);
            return code == 0 && headers["Content-Type"] == "application/timestamp-query"
                ? TestServer.Response(200, "OK", File.ReadAllBytes(r), "Content-Type: application/timestamp-reply")
                : TestServer.Response(500, "Error", Encoding.UTF8.GetBytes(output));
        });

        using var transport = new HttpTransport();
        var client = new TsaClient(new Fetcher(transport, new FetchOptions { Cache = null }));
        byte[] data = RandomNumberGenerator.GetBytes(4000);
        HashAlgorithmName name = hash == "sha256" ? HashAlgorithmName.SHA256 : hash == "sha384" ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA512;
        TimestampResult r = await client.StampAsync(new Uri($"http://127.0.0.1:{shim.Port}/tsa"), data, name, new TimestampRequestOptions
        {
            CertReq = certReq,
            Policy = "1.2.3.4.5",
            Verify = new TimeStampVerifyOptions { ExtraCertificates = certReq ? [] : [tsa, W.Intermediate.Certificate], TrustAnchors = [TrustAnchor.FromCertificate(W.Root.Certificate)] },
        });
        Assert.True(r.IsGranted, r.Reason + " " + r.Fetch.Reason);
        Assert.True(r.ContentTypeMatched);
        Assert.Equal("1.2.3.4.5", r.Report!.Info!.Policy);
        Assert.Contains("chains to a supplied anchor", r.Report.Find("trust")!.Reason, StringComparison.Ordinal);
        Assert.True(r.Report.Info.Ordering);
    }

    [Theory]
    [InlineData("sha256", true)]
    [InlineData("sha512", false)]
    public async Task OpenSslVerifiesWhatOurAuthorityIssuesOverHttp(string hash, bool nonce)
    {
        OpenSslTool.RequireOrSkip();
        string dir = Dir("ts-b");
        byte[] data = RandomNumberGenerator.GetBytes(3000);
        string dataFile = IssuanceKit.Write(dir, "data.bin", data);
        string q = Path.Combine(dir, "q.tsq");
        var args = new List<string> { "ts", "-query", "-data", dataFile, "-" + hash, "-cert", "-out", q };
        if (!nonce)
        {
            args.Add("-no_nonce");
        }

        IssuanceKit.Ok(OpenSslTool.Run([.. args]), "ts -query");
        using var host = new TestServer((_, _, body) => TestServer.Response(200, "OK", W.Tsa.Handle(body, World.Now).Encoded.ToArray(), "Content-Type: application/timestamp-reply"));

        // openssl builds the query and checks the reply; the bytes in between travel by HTTP through our fetcher to our handler.
        using var transport = new HttpTransport();
        FetchResult f = await new Fetcher(transport, new FetchOptions { Cache = null }).FetchAsync(new FetchRequest
        {
            Uri = new Uri($"http://127.0.0.1:{host.Port}/"),
            Method = "POST",
            Body = File.ReadAllBytes(q),
            Headers = [new("Content-Type", "application/timestamp-query")],
        });
        Assert.True(f.IsSuccess, f.Reason);
        string tsr = IssuanceKit.Write(dir, "r.tsr", f.Body.ToArray());
        IssuanceKit.Write(dir, "root.pem", W.Root.Certificate.ToPem());
        IssuanceKit.Write(dir, "untrusted.pem", W.Intermediate.Certificate.ToPem() + W.TsaCertificate.ToPem());
        (int code, string output) = OpenSslTool.Run("ts", "-verify", "-in", tsr, "-queryfile", q, "-CAfile", Path.Combine(dir, "root.pem"), "-untrusted", Path.Combine(dir, "untrusted.pem"), "-attime", World.Now.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture));
        Assert.True(code == 0, "ts -verify: " + output);
        Assert.Contains("Verification: OK", output, StringComparison.Ordinal);
    }
}
