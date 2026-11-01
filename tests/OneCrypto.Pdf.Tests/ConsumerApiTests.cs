using OnePdf;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Tsp;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Pdf.Tests;

/// <summary>The one-call B-LTA path, and the non-nullable accessors the straight-line recipes use.</summary>
public class ConsumerApiTests
{
    private static readonly PadesKit Kit = PadesKit.Shared;

    private sealed class LaterRevocation : IRevocationSource
    {
        private readonly RevocationData _data;

        public LaterRevocation(RevocationData data) => _data = data;

        public int Calls { get; private set; }

        public ValueTask<RevocationData> GetRevocationDataAsync(Certificate certificate, Certificate issuer, IReadOnlyList<string> crlUris, IReadOnlyList<string> ocspUris, CancellationToken cancellationToken)
        {
            Calls++;
            return ValueTask.FromResult(_data);
        }
    }

    private static PadesVerifyOptions RequireRevocation(DateTimeOffset at) =>
        Kit.Verify(at, null, static o => new PadesVerifyOptions { TrustAnchors = o.TrustAnchors, Intermediates = o.Intermediates, ReferenceTime = o.ReferenceTime, RevocationRequired = RevocationScope.EndEntity });

    private static PadesSignatureReport TheSignature(byte[] pdf, PadesVerifyOptions options)
    {
        using PdfDocument doc = PdfDocument.Open(pdf);
        return doc.VerifyPades(options).Signatures.First(static s => s.Kind == PadesSignatureKind.Signature);
    }

    [Fact]
    public async Task SigningAndCollectingRevocationAfterTheTimestampReachesBLtaInOneCall()
    {
        TestSigner signer = Kit.Signer(KeyKind.P256);
        DateTimeOffset stamped = Kit.Now;
        DateTimeOffset checkedAt = stamped.AddMinutes(10);

        // Revocation data the CA published before the signature was time-stamped, the only kind a one-step B-LTA signature can carry.
        RevocationData before = PadesKit.Merge(Kit.Crls(stamped.AddMinutes(-10)), Kit.Ocsp(stamped.AddMinutes(-10), signer.Certificate, Kit.TsaCertificate));
        // What the CA publishes later.
        RevocationData after = PadesKit.Merge(Kit.Crls(checkedAt.AddMinutes(-1)), Kit.Ocsp(checkedAt.AddMinutes(-1), signer.Certificate, Kit.TsaCertificate));

        // The authority's clock: the signature is stamped at `stamped`, the archive time-stamp ten minutes later, after the store is written.
        int stamps = 0;
        var common = new PadesSignOptions { Timestamp = Kit.Tsa(() => stamps++ == 0 ? stamped : checkedAt), ReferenceTime = stamped };

        // One step: the store holds only older data, so revocation at the time-stamp is not established and the signature is not valid with revocation required.
        byte[] oneStep;
        using (PdfDocument doc = PdfDocument.Open(PadesKit.Pdf(), new PdfOpenOptions { AllowEditing = true }))
        using (var ms = new MemoryStream())
        {
            doc.SignPades(ms, signer.Key, signer.Certificate, signer.Chain, new PadesSignOptions { Level = PadesLevel.LongTermArchive, Timestamp = Kit.Tsa(stamped), ReferenceTime = stamped, ValidationData = Kit.Validation(stamped, before) });
            oneStep = ms.ToArray();
        }

        Assert.False(TheSignature(oneStep, RequireRevocation(checkedAt.AddHours(1))).IsValid);

        // The helper: sign, time-stamp, ask the source afterwards, store, archive time-stamp.
        var source = new LaterRevocation(after);
        PadesValidationData afterStamp = new()
        {
            TrustAnchors = [Kit.Anchor],
            Intermediates = Kit.Chain,
            ReferenceTime = checkedAt,
            RevocationSource = source,
        };
        byte[] archive;
        PadesSignResult result;
        using (PdfDocument doc = PdfDocument.Open(PadesKit.Pdf(), new PdfOpenOptions { AllowEditing = true }))
        using (var ms = new MemoryStream())
        {
            result = await doc.SignPadesArchiveAsync(ms, signer.Key, signer.Certificate, signer.Chain, common, afterStamp);
            archive = ms.ToArray();
        }

        Assert.Equal(PadesLevel.LongTermArchive, result.Level);
        Assert.Equal(3, result.Revisions);
        Assert.True(source.Calls > 0, "the source is asked after the time-stamp, by the helper");
        PadesSignatureReport sig = TheSignature(archive, RequireRevocation(checkedAt.AddHours(1)));
        Assert.True(sig.IsValid, string.Join("; ", sig.Checks.Where(static c => c.Status is CmsCheckStatus.Failed or CmsCheckStatus.Unsupported).Select(static c => c.Rule + ": " + c.Reason)));
        Assert.Equal(PadesLevel.LongTermArchive, sig.Level);
        Assert.Equal(RevocationStatus.Good, sig.Chain!.SelectedPath!.Certificates[^1].Revocation.Status);
    }

    [Fact]
    public void TheSynchronousTwinWorksAndNeedsATimestampFunction()
    {
        TestSigner signer = Kit.Signer(KeyKind.P256);
        DateTimeOffset at = Kit.Now;
        PadesValidationData data = Kit.Validation(at.AddMinutes(5), PadesKit.Merge(Kit.Crls(at.AddMinutes(1)), Kit.Ocsp(at.AddMinutes(1), signer.Certificate, Kit.TsaCertificate)));
        using var doc = PdfDocument.Open(PadesKit.Pdf(), new PdfOpenOptions { AllowEditing = true });
        using var ms = new MemoryStream();
        PadesException e = Assert.Throws<PadesException>(() => doc.SignPadesArchive(ms, signer.Key, signer.Certificate, signer.Chain, new PadesSignOptions(), data));
        Assert.Equal(PadesError.NoTimestampFunction, e.Reason);
        Assert.Equal(0, ms.Length);

        PadesSignResult r = doc.SignPadesArchive(ms, signer.Key, signer.Certificate, signer.Chain, new PadesSignOptions { Timestamp = Kit.Tsa(at) }, data);
        Assert.Equal(PadesLevel.LongTermArchive, r.Level);
    }

    [Fact]
    public void TheStraightLineAccessorsNeedNoNullChecksAndFailWithATypedError()
    {
        TestSigner signer = Kit.Signer(KeyKind.P256);
        DateTimeOffset at = Kit.Now;
        byte[] pdf = PadesRoundTripTests.Sign(signer, new PadesSignOptions { Level = PadesLevel.Timestamped, Timestamp = Kit.Tsa(at), ReferenceTime = at });

        using PdfDocument doc = PdfDocument.Open(pdf);
        PdfSignature signature = doc.GetSignatures()[0];
        using (Stream signed = signature.OpenSignedDataOrThrow())
        {
            Assert.True(signed.Length > 0);
        }

        Assert.True(signature.TryOpenSignedData(out Stream? s));
        s!.Dispose();

        PadesTimestamp ts = doc.VerifyPades(Kit.Verify(at.AddHours(1))).Signatures[0].Timestamps.Single(static t => !t.IsDocument);
        Assert.True(ts.TryGetReport(out TimeStampReport? report));
        Assert.Same(report, ts.RequireReport());
        Assert.NotNull(ts.RequireToken());
        Assert.NotNull(report!.RequireToken());

        // A time-stamp whose value did not parse has no report: the accessor says so with PadesException, not a NullReferenceException.
        var broken = new PadesTimestamp(false, null, null, [], 0, 0, false);
        Assert.False(broken.TryGetReport(out _));
        Assert.Equal(PadesError.NotPresent, Assert.Throws<PadesException>(() => broken.RequireReport()).Reason);
        Assert.Equal(PadesError.NotPresent, Assert.Throws<PadesException>(() => broken.RequireToken()).Reason);
    }

    private sealed class TsaOverHttp : ITransport
    {
        private readonly DateTimeOffset _at;

        public TsaOverHttp(DateTimeOffset at) => _at = at;

        public int Posts { get; private set; }

        public ValueTask<TransportResponse> SendAsync(TransportRequest request, CancellationToken cancellationToken)
        {
            Posts++;
            Assert.Equal("POST", request.Method);
            byte[] reply = Kit.Authority.Handle(request.Body, _at).Encoded.ToArray();
            return ValueTask.FromResult(new TransportResponse(200, [new("Content-Type", "application/timestamp-reply")], new MemoryStream(reply)));
        }
    }

    [Fact]
    public void TheTimestampClientPlugsStraightIntoTheBridgeOptions()
    {
        TestSigner signer = Kit.Signer(KeyKind.P256);
        DateTimeOffset at = Kit.Now;
        var net = new TsaOverHttp(at);
        var tsa = new TsaClient(new Fetcher(net, new FetchOptions { Cache = null }), new Uri("http://tsa.test/"));

        // The line the recipe shows: no hand-written HTTP.
        var options = new PadesSignOptions { Level = PadesLevel.Timestamped, Timestamp = tsa.GetTimestampAsync, ReferenceTime = at };
        byte[] pdf = PadesRoundTripTests.Sign(signer, options);

        Assert.Equal(1, net.Posts);
        PadesSignatureReport sig = TheSignature(pdf, Kit.Verify(at.AddHours(1)));
        Assert.True(sig.IsValid);
        Assert.Equal(PadesLevel.Timestamped, sig.Level);
    }
}
