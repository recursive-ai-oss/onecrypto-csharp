using OneCrypto.Tests.Support;

namespace RecursiveAI.OneCrypto.Pdf.Tests;

/// <summary>A second black-box reader: poppler's <c>pdfsig</c>, when it is installed, checks the signature value over the byte ranges.</summary>
public class PdfsigTests
{
    private static readonly PadesKit Kit = PadesKit.Shared;

    [Theory]
    [InlineData(KeyKind.Rsa2048)]
    [InlineData(KeyKind.P256)]
    [InlineData(KeyKind.P384)]
    public void PdfsigAcceptsTheSignatureAndRefusesATamperedFile(KeyKind kind)
    {
        string? exe = ToolRunner.Find("pdfsig");
        Assert.SkipWhen(exe is null, "pdfsig is not installed");
        TestSigner signer = Kit.Signer(kind);
        byte[] pdf = PadesRoundTripTests.Sign(signer, new PadesSignOptions { Level = PadesLevel.Timestamped, ReferenceTime = Kit.Now, Timestamp = Kit.Tsa(Kit.Now) });
        string dir = ToolRunner.TempDir("pdfsig");
        File.WriteAllBytes(Path.Combine(dir, "good.pdf"), pdf);
        byte[] bad = (byte[])pdf.Clone();
        bad[System.Text.Encoding.Latin1.GetString(bad).IndexOf("Hello, signature", StringComparison.Ordinal)] = (byte)'J';
        File.WriteAllBytes(Path.Combine(dir, "bad.pdf"), bad);
        (_, string good) = ToolRunner.Run(exe!, dir, "good.pdf");
        (_, string tampered) = ToolRunner.Run(exe!, dir, "bad.pdf");
        Assert.Contains("Signature is Valid", good, StringComparison.Ordinal);
        Assert.Contains("Digest Mismatch", tampered, StringComparison.Ordinal);
    }
}
