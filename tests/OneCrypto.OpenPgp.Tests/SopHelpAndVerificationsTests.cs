using System.Text;
using RecursiveAI.OneCrypto.Cli.Sop;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>The help text of <c>sop</c> and the optional JSON field on VERIFICATIONS lines (draft §7.10.1).</summary>
// The sop commands spool through the temp directory, which DecryptionReviewTests redirects process-wide; run them in the same serial collection.
[Collection("ProcessMemory")]
public class SopHelpAndVerificationsTests
{
    private sealed record Result(int Code, string Out, string Err);

    private static Result Sop(byte[] stdin, params string[] args)
    {
        using var inStream = new MemoryStream(stdin);
        using var outStream = new MemoryStream();
        var err = new StringWriter();
        int code = SopApp.Run(args, new SopIo(inStream, outStream, err, _ => null));
        return new Result(code, Encoding.UTF8.GetString(outStream.ToArray()), err.ToString());
    }

    [Theory]
    [InlineData("--help")]
    [InlineData("-h")]
    [InlineData("help")]
    public void HelpListsEverySubcommandAndSucceeds(string flag)
    {
        Result r = Sop([], flag);
        Assert.Equal(0, r.Code);
        foreach (string sub in new[] { "version", "list-profiles", "generate-key", "change-key-password", "revoke-key", "extract-cert", "update-key", "merge-certs", "certify-userid", "validate-userid", "sign", "verify", "encrypt", "decrypt", "inline-sign", "inline-verify", "inline-detach", "armor", "dearmor" })
        {
            Assert.Contains("  " + sub + " ", r.Out, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void EveryHelpTextFitsEightyColumns()
    {
        var texts = new List<string> { SopHelp.ForTool(), SopHelp.ForSop([], sopv: false), SopHelp.ForSop([], sopv: true) };
        foreach (string name in new[] { "version", "list-profiles", "generate-key", "change-key-password", "revoke-key", "extract-cert", "update-key", "merge-certs", "certify-userid", "validate-userid", "sign", "verify", "encrypt", "decrypt", "inline-sign", "inline-verify", "inline-detach", "armor", "dearmor" })
        {
            texts.Add(SopHelp.ForSop([name, "--help"], sopv: false));
            texts.Add(SopHelp.ForSop([name, "--help"], sopv: true));
        }

        foreach (string text in texts)
        {
            foreach (string line in text.Split('\n'))
            {
                Assert.True(line.Length <= SopHelp.MaxWidth, $"{line.Length} columns: {line}");
            }
        }

        // A wrapped option list keeps every option and indents the continuation.
        string update = SopHelp.ForSop(["update-key", "--help"], sopv: false);
        Assert.Contains("--merge-certs=CERT...", update, StringComparison.Ordinal);
    }

    [Fact]
    public void HelpForOneSubcommandShowsItsOptions()
    {
        Result r = Sop([], "generate-key", "--help");
        Assert.Equal(0, r.Code);
        Assert.Contains("--profile=P", r.Out, StringComparison.Ordinal);
        Assert.Equal(r.Out, Sop([], "help", "generate-key").Out);
    }

    [Fact]
    public void SopvHelpListsOnlyTheVerificationSubset()
    {
        using var inStream = new MemoryStream();
        using var outStream = new MemoryStream();
        Assert.Equal(0, SopApp.Run(["--help"], new SopIo(inStream, outStream, new StringWriter(), _ => null), sopvOnly: true));
        string text = Encoding.UTF8.GetString(outStream.ToArray());
        Assert.Contains("  inline-verify ", text, StringComparison.Ordinal);
        Assert.DoesNotContain("  generate-key ", text, StringComparison.Ordinal);
    }

    [Fact]
    public void VerifyNamesTheCertsObjectsThatCouldHaveSigned()
    {
        string dir = Path.Combine(Path.GetTempPath(), "sop-ver-" + Environment.ProcessId + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        // Windows file names cannot contain a double quote.
        string key = Path.Combine(dir, OperatingSystem.IsWindows() ? "alice q.key" : "alice \"q\".key");
        byte[] keyBytes = Encoding.UTF8.GetBytes(Sop([], "generate-key", "Alice <alice@example.org>").Out);
        File.WriteAllBytes(key, keyBytes);
        string cert = Path.Combine(dir, "alice.cert");
        File.WriteAllText(cert, Sop(keyBytes, "extract-cert").Out);
        string copy = Path.Combine(dir, "same-again.cert");
        File.Copy(cert, copy);
        string other = Path.Combine(dir, "bob.cert");
        byte[] bobKey = Encoding.UTF8.GetBytes(Sop([], "generate-key", "Bob <bob@example.org>").Out);
        File.WriteAllText(other, Sop(bobKey, "extract-cert").Out);

        byte[] msg = "hello"u8.ToArray();
        string sig = Path.Combine(dir, "m.sig");
        File.WriteAllText(sig, Sop(msg, "sign", key).Out);

        Result v = Sop(msg, "verify", sig, other, cert, copy);
        Assert.Equal(0, v.Code);
        string line = Assert.Single(v.Out.TrimEnd('\n').Split('\n'));
        string[] fields = line.Split(' ', 5);
        Assert.Equal(5, fields.Length);
        Assert.Equal("mode:binary", fields[3]);
        // Only the certificates that hold the signer are named, in the order given; the one that does not is left out.
        using System.Text.Json.JsonDocument doc = System.Text.Json.JsonDocument.Parse(fields[4]);
        Assert.Equal([cert, copy], doc.RootElement.GetProperty("signers").EnumerateArray().Select(e => e.GetString()).ToArray());
        Assert.StartsWith("{\"signers\":[\"", fields[4], StringComparison.Ordinal);
    }

    [Fact]
    public void ControlCharactersAndQuotesInNamesAreEscaped()
    {
        var sb = new StringBuilder();
        CertOrigins.AppendJsonString(sb, "a\"b\\c\nd");
        Assert.Equal("\"a\\\"b\\\\c\\u000ad\"", sb.ToString());
    }
}
