using OneCrypto.Online.Tests.Csc;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.Online.Csc;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Pdf.Tests;

/// <summary>A PAdES signature whose key lives in a remote signing service: the bridge hands the digest of the signed attributes to the CSC key, and the result validates.</summary>
public class PadesCscTests
{
    private static readonly PadesKit Kit = PadesKit.Shared;

    private static async Task<(TestSigner Remote, CscTestServer Server)> RemoteSigner(KeyKind kind, int scal)
    {
        TestSigner local = Kit.Signer(kind);
        var clock = new FixedClock(Kit.Now);
        var server = new CscTestServer(clock.GetUtcNow);
        server.Add(new CscTestCredential { Id = "PADES", Key = local.Key, Chain = [local.Certificate, .. local.Chain], Scal = scal, Pin = "13579" });
        string token = server.IssueServiceToken(TimeSpan.FromHours(1));
        var client = new CscClient(new Fetcher(new CscTestTransport(server, new Uri("https://csc.test/csc/v2/"))), new Uri("https://csc.test/csc/v2/"), new CscStaticTokenSource(new CscAccessToken(token)));
        var keyOptions = new CscKeyOptions { AuthDataProvider = (_, _) => ValueTask.FromResult<IReadOnlyList<CscAuthObject>>([new CscAuthObject("PIN", "13579")]) };
        CscResult<CscSigningKey> opened = await client.OpenSigningKeyAsync("PADES", keyOptions);
        Assert.True(opened.IsSuccess, opened.Reason);
        return (local with { Key = opened.Value! }, server);
    }

    private sealed class FixedClock : TimeProvider
    {
        private readonly DateTimeOffset _now;

        public FixedClock(DateTimeOffset now) => _now = now;

        public override DateTimeOffset GetUtcNow() => _now;
    }

    [Theory]
    [InlineData(KeyKind.Rsa2048, false, 1)]
    [InlineData(KeyKind.Rsa2048, true, 2)]
    [InlineData(KeyKind.P256, false, 2)]
    [InlineData(KeyKind.P384, false, 1)]
    public async Task APadesSignatureWithARemoteKeyValidatesAndPdfsigAcceptsIt(KeyKind kind, bool pss, int scal)
    {
        (TestSigner remote, CscTestServer server) = await RemoteSigner(kind, scal);
        DateTimeOffset at = Kit.Now;
        var options = new PadesSignOptions { Level = PadesLevel.LongTermArchive, RsaPss = pss, ReferenceTime = at, Timestamp = Kit.Tsa(at), ValidationData = Kit.Validation(at, PadesKit.Merge(Kit.Crls(at), Kit.Ocsp(at, remote.Certificate, Kit.TsaCertificate))) };

        byte[] pdf = PadesRoundTripTests.Sign(remote, options);

        PadesReport report = PadesRoundTripTests.Verify(pdf, Kit.Verify(at.AddHours(1)));
        PadesSignatureReport sig = report.Signatures.Single(static s => s.Kind == PadesSignatureKind.Signature);
        Assert.True(sig.IsValid, string.Join("; ", sig.Checks.Where(static c => c.Status is CmsCheckStatus.Failed or CmsCheckStatus.Unsupported).Select(static c => c.Rule + ": " + c.Reason)));
        Assert.Equal(PadesLevel.LongTermArchive, sig.Level);
        Assert.True(report.AllValid, report.Summary);

        // One authorization and one signing call, carrying a digest: the document never reached the service.
        Assert.Single(server.Calls, static c => c.Path == "signatures/signHash");
        Assert.Single(server.Calls, static c => c.Path == "credentials/authorize");

        string? exe = ToolRunner.Find("pdfsig");
        if (exe is not null)
        {
            string dir = ToolRunner.TempDir("pdfsig-csc");
            File.WriteAllBytes(Path.Combine(dir, "csc.pdf"), pdf);
            (_, string output) = ToolRunner.Run(exe, dir, "csc.pdf");
            Assert.Contains("Signature is Valid", output, StringComparison.Ordinal);
        }
    }
}
