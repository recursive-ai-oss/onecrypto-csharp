using System.Text;
using RecursiveAI.OneCrypto.Cli.Sop;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>The sop subcommands that need only the packet layer, driven in process.</summary>
public class SopTests
{
    private sealed record Result(int Code, byte[] Out, string Err);

    private static Result Sop(byte[] stdin, params string[] args)
    {
        using var inStream = new MemoryStream(stdin);
        using var outStream = new MemoryStream();
        var err = new StringWriter();
        int code = SopApp.Run(args, new SopIo(inStream, outStream, err, _ => null));
        return new Result(code, outStream.ToArray(), err.ToString());
    }

    private static Result SopEnv(byte[] stdin, Dictionary<string, string> env, params string[] args)
    {
        using var inStream = new MemoryStream(stdin);
        using var outStream = new MemoryStream();
        var err = new StringWriter();
        int code = SopApp.Run(args, new SopIo(inStream, outStream, err, n => env.GetValueOrDefault(n)));
        return new Result(code, outStream.ToArray(), err.ToString());
    }

    private static string Scratch(string name, byte[] data)
    {
        string dir = Path.Combine(Path.GetTempPath(), "sop-msg-" + Environment.ProcessId);
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, name);
        File.WriteAllBytes(path, data);
        return path;
    }

    [Fact]
    public void SignVerifyEncryptDecryptThroughSop()
    {
        string key = Scratch("alice.key", Vector("A_4.asc"));
        byte[] cert = Sop(File.ReadAllBytes(key), "extract-cert").Out;
        string certPath = Scratch("alice.cert", cert);
        byte[] msg = "Hello, sop!\r\nsecond line\n"u8.ToArray();

        Result sig = Sop(msg, "sign", "--as=text", key);
        Assert.Equal(0, sig.Code);
        string sigPath = Scratch("msg.sig", sig.Out);
        Result v = Sop(msg, "verify", sigPath, certPath);
        Assert.Equal(0, v.Code);
        Assert.Contains("mode:text", Encoding.ASCII.GetString(v.Out), StringComparison.Ordinal);
        Assert.Equal(3, Sop("Tampered"u8.ToArray(), "verify", sigPath, certPath).Code);
        Assert.Equal(19, Sop(msg, "verify", sigPath).Code);

        foreach (string mode in new[] { "binary", "text", "clearsigned" })
        {
            Result inl = Sop(msg, "inline-sign", "--as=" + mode, key);
            Assert.Equal(0, inl.Code);
            Result back = Sop(inl.Out, "inline-verify", certPath);
            Assert.Equal(0, back.Code);
            string expected = mode == "clearsigned" ? "Hello, sop!\nsecond line" : "Hello, sop!\r\nsecond line\n";
            Assert.Equal(expected, Encoding.UTF8.GetString(back.Out));
        }

        Result enc = Sop(msg, "encrypt", "--sign-with=" + key, certPath);
        Assert.Equal(0, enc.Code);
        string vout = Path.Combine(Path.GetDirectoryName(key)!, "v-" + Guid.NewGuid().ToString("N"));
        Result dec = Sop(enc.Out, "decrypt", "--verifications-out=" + vout, "--verify-with=" + certPath, key);
        Assert.Equal(0, dec.Code);
        Assert.Equal(msg, dec.Out);
        Assert.Contains("mode:binary", File.ReadAllText(vout), StringComparison.Ordinal);

        var env = new Dictionary<string, string> { ["PW"] = "hunter2\n" };
        Result pw = SopEnv(msg, env, "encrypt", "--no-armor", "--with-password=@ENV:PW", "--profile=rfc4880");
        Assert.Equal(0, pw.Code);
        Assert.Equal(msg, SopEnv(pw.Out, env, "decrypt", "--with-password=@ENV:PW").Out);
        Assert.Equal(29, SopEnv(pw.Out, new Dictionary<string, string> { ["PW"] = "nope" }, "decrypt", "--with-password=@ENV:PW").Code);
    }

    [Fact]
    public void ValueOptionsAcceptTheValueAsTheNextArgument()
    {
        // Other implementations and the interoperability suite write `--with-password VALUE`; both forms must mean the same.
        var env = new Dictionary<string, string> { ["PW"] = "secret" };
        byte[] msg = "hello"u8.ToArray();
        Result enc = SopEnv(msg, env, "encrypt", "--no-armor", "--with-password", "@ENV:PW", "--profile", "rfc4880");
        Assert.Equal(0, enc.Code);
        Assert.Equal(msg, SopEnv(enc.Out, env, "decrypt", "--with-password", "@ENV:PW").Out);
    }

    private static byte[] Vector(string name) => File.ReadAllBytes(TestFiles.OpenPgp("rfc9580", name));

    private static string Label(byte[] armor) => Encoding.ASCII.GetString(armor).Split('\n')[0];

    [Fact]
    public void VersionNamesTheToolAndRefusesTheSopvSubset()
    {
        Result r = Sop([], "version");
        Assert.Equal(0, r.Code);
        Assert.StartsWith("onecrypto ", Encoding.UTF8.GetString(r.Out), StringComparison.Ordinal);
        Assert.StartsWith("~draft-dkg-openpgp-stateless-cli-", Encoding.UTF8.GetString(Sop([], "version", "--sop-spec").Out), StringComparison.Ordinal);
        Assert.Equal(37, Sop([], "version", "--sopv").Code);
        Assert.Equal(83, Sop([], "version", "--backend", "--extended").Code);
        Assert.Equal(37, Sop([], "version", "--bogus").Code);
    }

    [Fact]
    public void UnimplementedAndUnknownSubcommandsExitWithUnsupportedSubcommand()
    {
        foreach (string sub in new[] { "generate-key", "merge-certs", "nonsense" })
        {
            Assert.Equal(69, Sop([], sub).Code);
        }

        Assert.StartsWith("rfc9580:", Encoding.UTF8.GetString(Sop([], "list-profiles", "encrypt").Out), StringComparison.Ordinal);
        foreach (string sub in new[] { "sign", "verify", "encrypt", "decrypt", "inline-verify", "inline-sign" })
        {
            Assert.Equal(19, Sop([], sub).Code);
        }

        Assert.Equal(89, Sop([], "list-profiles", "armor").Code);
        Assert.Equal(19, Sop([], "list-profiles").Code);
    }

    [Theory]
    [InlineData("A_3.asc", "-----BEGIN PGP PUBLIC KEY BLOCK-----")]
    [InlineData("A_4.asc", "-----BEGIN PGP PRIVATE KEY BLOCK-----")]
    [InlineData("A_6.asc", "-----BEGIN PGP SIGNATURE-----")]
    [InlineData("A_7.asc", "-----BEGIN PGP MESSAGE-----")]
    [InlineData("A_8_5.asc", "-----BEGIN PGP MESSAGE-----")]
    [InlineData("A_10_5.asc", "-----BEGIN PGP MESSAGE-----")]
    public void ArmorChoosesTheLabelFromThePackets(string file, string label)
    {
        byte[] binary = TestFiles.ReadArmored(TestFiles.OpenPgp("rfc9580", file));
        Result r = Sop(binary, "armor");
        Assert.Equal(0, r.Code);
        Assert.Equal(label, Label(r.Out));
        Assert.Equal(binary, Armor.Decode(r.Out).Data);

        // Armor is idempotent, and dearmor undoes it.
        Assert.Equal(r.Out, Sop(r.Out, "armor").Out);
        Assert.Equal(binary, Sop(r.Out, "dearmor").Out);
        Assert.Equal(binary, Sop(binary, "dearmor").Out);
    }

    [Fact]
    public void ArmorRefusesWhatIsNotAPacketStream()
    {
        Assert.Equal(41, Sop([], "armor").Code);
        Assert.Equal(41, Sop("hello, this is not OpenPGP"u8.ToArray(), "armor").Code);
        Assert.Equal(41, Sop([0xC0 | 13, 1, (byte)'x'], "armor").Code);
        Assert.Equal(41, Sop([0xC0 | 6, 50, 4], "dearmor").Code);
        Assert.Equal(41, Sop(Encoding.ASCII.GetBytes("-----BEGIN PGP MESSAGE-----\n\nAAAA\n-----END PGP MESSAGE-----\n"), "dearmor").Code);
        Assert.Equal(37, Sop([], "armor", "--label=key").Code);
    }

    [Fact]
    public void ArmorOfSignaturesFollowedByDataIsAMessage()
    {
        byte[] message = TestFiles.ReadArmored(TestFiles.OpenPgp("rfc9580", "A_7.asc"));
        IReadOnlyList<Packet> packets = PacketParser.ParseAll(message);
        using var ms = new MemoryStream();
        packets[2].WriteTo(ms);
        packets[1].WriteTo(ms);
        Assert.StartsWith("-----BEGIN PGP MESSAGE-----", Label(Sop(ms.ToArray(), "armor").Out) + "", StringComparison.Ordinal);
    }

    [Fact]
    public void StrictArmorRulesApplyToInput()
    {
        byte[] armored = Vector("A_3.asc");
        Assert.Equal(0, Sop(armored, "dearmor").Code);
        Assert.Equal(41, Sop([.. "some text\n"u8, .. armored], "dearmor").Code);
        Assert.Equal(41, Sop([.. armored, .. "trailing\n"u8], "dearmor").Code);
        Assert.Equal(0, Sop([.. "\n"u8, .. armored, .. "  \n\n"u8], "dearmor").Code);
    }

    [Fact]
    public void ExtractCertTurnsASecretKeyIntoTheCertificate()
    {
        Result r = Sop(Vector("A_4.asc"), "extract-cert");
        Assert.Equal(0, r.Code);
        Assert.Equal("-----BEGIN PGP PUBLIC KEY BLOCK-----", Label(r.Out));
        Assert.Equal(TestFiles.ReadArmored(TestFiles.OpenPgp("rfc9580", "A_3.asc")), Armor.Decode(r.Out).Data);
        Result bin = Sop(Vector("A_4.asc"), "extract-cert", "--no-armor");
        Assert.Equal(Armor.Decode(r.Out).Data, bin.Out);

        // Two keys in, two certificates out; and the locked key works the same way.
        byte[] two = [.. TestFiles.ReadArmored(TestFiles.OpenPgp("rfc9580", "A_4.asc")), .. TestFiles.ReadArmored(TestFiles.OpenPgp("rfc9580", "A_5.asc"))];
        Result both = Sop(two, "extract-cert", "--no-armor");
        Assert.Equal(0, both.Code);
        Assert.Equal(2, TransferableKey.ParseAll(PacketParser.ParseAll(both.Out)).Count);
    }

    [Fact]
    public void ExtractCertRefusesCertificatesAndGarbage()
    {
        Assert.Equal(41, Sop(Vector("A_3.asc"), "extract-cert").Code);
        Assert.Equal(41, Sop(Vector("A_6.asc"), "extract-cert").Code);
        Assert.Equal(41, Sop([], "extract-cert").Code);
    }

    [Fact]
    public void InlineDetachSplitsAnInlineSignedMessage()
    {
        string path = Path.Combine(Path.GetTempPath(), "sop-sigs-" + Guid.NewGuid().ToString("N"));
        try
        {
            Result r = Sop(Vector("A_7.asc"), "inline-detach", "--signatures-out=" + path);
            Assert.Equal(0, r.Code);
            Assert.Equal("What we need from the grocery store:\n\n- tofu\n- vegetables\n- noodles\n", Encoding.UTF8.GetString(r.Out));
            byte[] sigs = File.ReadAllBytes(path);
            Assert.Equal("-----BEGIN PGP SIGNATURE-----", Label(sigs));
            Assert.Single(PacketParser.ParseAll(Armor.Decode(sigs).Data).OfType<SignaturePacket>());

            // The output file now exists, which is a refusal.
            Assert.Equal(59, Sop(Vector("A_7.asc"), "inline-detach", "--signatures-out=" + path).Code);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void InlineDetachReadsTheCleartextSignatureFramework()
    {
        string path = Path.Combine(Path.GetTempPath(), "sop-sigs-" + Guid.NewGuid().ToString("N"));
        try
        {
            Result r = Sop(Vector("A_6_cleartext.asc"), "inline-detach", "--no-armor", "--signatures-out=" + path);
            Assert.Equal(0, r.Code);
            // Dash-escaping is removed, and the line ending before the signature belongs to the framework.
            Assert.Equal("What we need from the grocery store:\n\n- tofu\n- vegetables\n- noodles\n", Encoding.UTF8.GetString(r.Out));
            Assert.Equal(PacketTag.Signature, PacketParser.ParseAll(File.ReadAllBytes(path)).Single().Tag);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void InlineDetachArgumentAndInputErrors()
    {
        Assert.Equal(19, Sop(Vector("A_7.asc"), "inline-detach").Code);
        Assert.Equal(71, Sop(Vector("A_7.asc"), "inline-detach", "--signatures-out=@ENV:NOPE").Code);
        string path = Path.Combine(Path.GetTempPath(), "sop-sigs-" + Guid.NewGuid().ToString("N"));
        try
        {
            Assert.Equal(41, Sop(Vector("A_3.asc"), "inline-detach", "--signatures-out=" + path).Code);
            File.Delete(path);
            Assert.Equal(41, Sop(Vector("A_6.asc"), "inline-detach", "--signatures-out=" + path).Code);
            File.Delete(path);
            Assert.Equal(41, Sop("plain text"u8.ToArray(), "inline-detach", "--signatures-out=" + path).Code);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void DoubleDashEndsOptionParsing()
    {
        // After "--" everything is positional, even a word that looks like an option; armor takes none.
        Assert.Equal(37, Sop(TestFiles.ReadArmored(TestFiles.OpenPgp("rfc9580", "A_3.asc")), "armor", "--", "--no-armor").Code);
        Assert.Equal(0, Sop(TestFiles.ReadArmored(TestFiles.OpenPgp("rfc9580", "A_3.asc")), "armor", "--").Code);
    }
}
