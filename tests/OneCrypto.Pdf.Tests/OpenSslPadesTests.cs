using System.Security.Cryptography;
using OnePdf;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace RecursiveAI.OneCrypto.Pdf.Tests;

/// <summary>The signatures and time-stamps the bridge writes, checked by openssl as a black box: <c>cms -verify</c> on the extracted CMS and <c>ts -verify</c> on each token.</summary>
public class OpenSslPadesTests
{
    private static readonly PadesKit Kit = PadesKit.Shared;

    private static (byte[] Cms, byte[] Signed, byte[] Contents) Pieces(byte[] pdf, int index, out PdfSignature signature)
    {
        using PdfDocument doc = PdfDocument.Open(pdf);
        signature = doc.GetSignatures()[index];
        Assert.True(PdfLayout.TryRanges(signature, pdf, out long a, out long b, out long c));
        Assert.True(PdfLayout.TryContentsBytes(pdf, a, b, out byte[] contents));
        byte[] signed = [.. pdf.AsSpan(0, (int)a), .. pdf.AsSpan((int)b, (int)c)];
        return (contents[..PdfLayout.DerLength(contents)], signed, contents);
    }

    private static string Dir(string name)
    {
        string d = Path.Combine(OpenSslTool.TempDir("pades"), name + "-" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(d);
        File.WriteAllText(Path.Combine(d, "root.pem"), Kit.Root.Certificate.ToPem());
        File.WriteAllText(Path.Combine(d, "chain.pem"), Kit.Intermediate.Certificate.ToPem());
        return d;
    }

    [Theory]
    [InlineData(KeyKind.Rsa2048, false)]
    [InlineData(KeyKind.Rsa2048, true)]
    [InlineData(KeyKind.P256, false)]
    [InlineData(KeyKind.P384, false)]
    [InlineData(KeyKind.Ed25519, false)]
    [InlineData(KeyKind.Ed448, false)]
    [InlineData(KeyKind.MlDsa65, false)]
    public void OpenSslVerifiesTheCmsOfEachLevelAndEveryTimestamp(KeyKind kind, bool pss)
    {
        OpenSslTool.RequireOrSkip();
        if (kind is KeyKind.Ed448 or KeyKind.MlDsa65)
        {
            OpenSslTool.RequireOrSkip(3, 5, "Ed448 and ML-DSA in CMS");
        }

        if (kind == KeyKind.MlDsa65 && !MLDsa.IsSupported)
        {
            return;
        }

        TestSigner signer = Kit.Signer(kind);
        DateTimeOffset at = Kit.Now;
        var options = new PadesSignOptions
        {
            Level = PadesLevel.LongTermArchive,
            RsaPss = pss,
            ReferenceTime = at,
            Timestamp = Kit.Tsa(at),
            ValidationData = Kit.Validation(at, PadesKit.Merge(Kit.Crls(at), Kit.Ocsp(at, signer.Certificate, Kit.TsaCertificate))),
        };
        byte[] pdf = PadesRoundTripTests.Sign(signer, options);
        string dir = Dir($"{kind}-{pss}");
        long attime = at.AddMinutes(5).ToUnixTimeSeconds();

        (byte[] cms, byte[] signed, _) = Pieces(pdf, 0, out PdfSignature sig);
        Assert.Equal("ETSI.CAdES.detached", sig.SubFilter);
        File.WriteAllBytes(Path.Combine(dir, "sig.der"), cms);
        File.WriteAllBytes(Path.Combine(dir, "signed.bin"), signed);
        (int code, string output) = OpenSslTool.RunIn(dir, "cms", "-verify", "-inform", "DER", "-in", "sig.der", "-content", "signed.bin", "-binary", "-CAfile", "root.pem", "-certfile", "chain.pem", "-attime", attime.ToString(System.Globalization.CultureInfo.InvariantCulture), "-out", "out.bin");
        Assert.True(code == 0, "openssl cms -verify: " + output);

        // The same signature over different content is refused.
        byte[] other = (byte[])signed.Clone();
        other[10] ^= 1;
        File.WriteAllBytes(Path.Combine(dir, "other.bin"), other);
        Assert.NotEqual(0, OpenSslTool.RunIn(dir, "cms", "-verify", "-inform", "DER", "-in", "sig.der", "-content", "other.bin", "-binary", "-CAfile", "root.pem", "-certfile", "chain.pem", "-attime", attime.ToString(System.Globalization.CultureInfo.InvariantCulture), "-out", "out2.bin").Code);

        // The signature time-stamp: its imprint is the hash of the signature value.
        var parsed = SignedData.Parse(cms);
        byte[] token = parsed.Signers[0].FindUnsigned(CmsOids.SignatureTimeStampToken)!.Values[0].ToArray();
        File.WriteAllBytes(Path.Combine(dir, "sigts.der"), token);
        string digest = Convert.ToHexString(SHA256.HashData(parsed.Signers[0].Signature.Span));
        VerifyToken(dir, "sigts.der", digest, attime);

        // The document time-stamp: its imprint is the hash of both byte ranges of the time-stamp's own dictionary.
        (byte[] tsCms, byte[] tsSigned, _) = Pieces(pdf, 1, out PdfSignature docTs);
        Assert.Equal("ETSI.RFC3161", docTs.SubFilter);
        File.WriteAllBytes(Path.Combine(dir, "docts.der"), tsCms);
        VerifyToken(dir, "docts.der", Convert.ToHexString(SHA256.HashData(tsSigned)), attime);
        Assert.NotEqual(0, OpenSslTool.RunIn(dir, "ts", "-verify", "-in", "docts.der", "-token_in", "-digest", new string('0', 64), "-CAfile", "root.pem", "-untrusted", "chain.pem", "-attime", attime.ToString(System.Globalization.CultureInfo.InvariantCulture)).Code);
    }

    private static void VerifyToken(string dir, string file, string digestHex, long attime)
    {
        (int code, string output) = OpenSslTool.RunIn(dir, "ts", "-verify", "-in", file, "-token_in", "-digest", digestHex, "-CAfile", "root.pem", "-untrusted", "chain.pem", "-attime", attime.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Assert.True(code == 0, "openssl ts -verify " + file + ": " + output);
    }
}
