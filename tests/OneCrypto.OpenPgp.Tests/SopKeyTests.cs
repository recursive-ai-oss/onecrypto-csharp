using System.Text;
using RecursiveAI.OneCrypto.Cli.Sop;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>generate-key, change-key-password, revoke-key, update-key, merge-certs, certify-userid and validate-userid driven in process.</summary>
[Collection("ProcessMemory")]
public class SopKeyTests
{
    private sealed record Result(int Code, byte[] Out, string Err);

    private static Result Sop(byte[] stdin, params string[] args) => SopEnv(stdin, [], args);

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
        string dir = Path.Combine(Path.GetTempPath(), "sop-key-" + Environment.ProcessId);
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, name);
        File.WriteAllBytes(path, data);
        return path;
    }

    private static string Text(Result r) => Encoding.ASCII.GetString(r.Out);

    [Theory]
    [InlineData("default")]
    [InlineData("rfc4880")]
    [InlineData("draft-koch-eddsa-for-openpgp-00")]
    [InlineData("rfc9580-v4")]
    [InlineData("nist-p256")]
    public void GeneratedKeysWorkThroughSop(string profile)
    {
        Result gen = Sop([], "generate-key", "--profile=" + profile, "Alice <alice@example.org>");
        Assert.Equal(0, gen.Code);
        Assert.StartsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----", Text(gen), StringComparison.Ordinal);
        string key = Scratch(profile + ".key", gen.Out);
        Result cert = Sop(gen.Out, "extract-cert");
        Assert.Equal(0, cert.Code);
        string certPath = Scratch(profile + ".cert", cert.Out);

        byte[] msg = "hello"u8.ToArray();
        Result sig = Sop(msg, "sign", key);
        Assert.Equal(0, sig.Code);
        Assert.Equal(0, Sop(msg, "verify", Scratch(profile + ".sig", sig.Out), certPath).Code);
        Result enc = Sop(msg, "encrypt", certPath);
        Assert.Equal(0, enc.Code);
        Result dec = Sop(enc.Out, "decrypt", key);
        Assert.Equal(0, dec.Code);
        Assert.Equal(msg, dec.Out);
    }

    [Fact]
    public void ProfilesAndSignMode()
    {
        Result list = Sop([], "list-profiles", "generate-key");
        Assert.Equal(0, list.Code);
        Assert.StartsWith("default:", Text(list), StringComparison.Ordinal);
        Assert.Equal(89, Sop([], "generate-key", "--profile=nonsense", "A").Code);
        Assert.Equal(89, Sop([], "list-profiles", "sign").Code);

        Result signingOnly = Sop([], "generate-key", "--signing-only", "--no-armor", "S");
        Assert.Equal(0, signingOnly.Code);
        PgpCertificate k = PgpCertificate.Parse(signingOnly.Out);
        Assert.Single(k.Keys);
        Result nothing = Sop([], "generate-key", "--no-armor");
        Assert.Equal(0, nothing.Code);
        Assert.Empty(PgpCertificate.Parse(nothing.Out).UserIds);
    }

    [Fact]
    public void PasswordsProtectChangeAndRemove()
    {
        var env = new Dictionary<string, string> { ["P1"] = "one\n", ["P2"] = "two" };
        Result gen = SopEnv([], env, "generate-key", "--with-key-password=@ENV:P1", "Pat");
        Assert.Equal(0, gen.Code);
        string lockedPath = Scratch("locked.key", gen.Out);
        Result certR = Sop(gen.Out, "extract-cert");
        string certPath = Scratch("locked.cert", certR.Out);
        Assert.Equal(67, Sop("x"u8.ToArray(), "sign", lockedPath).Code);
        Assert.Equal(0, SopEnv("x"u8.ToArray(), env, "sign", "--with-key-password=@ENV:P1", lockedPath).Code);

        Result changed = SopEnv(gen.Out, env, "change-key-password", "--old-key-password=@ENV:P1", "--new-key-password=@ENV:P2");
        Assert.Equal(0, changed.Code);
        Assert.Equal(67, SopEnv("x"u8.ToArray(), env, "sign", "--with-key-password=@ENV:P1", Scratch("c.key", changed.Out)).Code);
        Assert.Equal(0, SopEnv("x"u8.ToArray(), env, "sign", "--with-key-password=@ENV:P2", Scratch("c.key2", changed.Out)).Code);

        Assert.Equal(67, SopEnv(changed.Out, env, "change-key-password", "--old-key-password=@ENV:P1").Code);
        Result open = SopEnv(changed.Out, env, "change-key-password", "--old-key-password=@ENV:P2");
        Assert.Equal(0, open.Code);
        Assert.Equal(0, Sop("x"u8.ToArray(), "sign", Scratch("open.key", open.Out)).Code);
        Assert.NotEmpty(certPath);

        // A new password that is not text is refused.
        var bad = new Dictionary<string, string>();
        string badFile = Scratch("bad.pw", [0xFF, 0xFE, 0xFD]);
        Assert.Equal(31, Sop(gen.Out, "change-key-password", "--new-key-password=" + badFile, "--old-key-password=" + Scratch("p1", "one"u8.ToArray())).Code);
        _ = bad;
    }

    [Fact]
    public void RevokeKeyMakesAnInvalidCertificate()
    {
        Result gen = Sop([], "generate-key", "Rev");
        Result revoked = Sop(gen.Out, "revoke-key");
        Assert.Equal(0, revoked.Code);
        Assert.StartsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----", Text(revoked), StringComparison.Ordinal);
        PgpCertificate c = PgpCertificate.Parse(revoked.Out);
        Assert.False(c.HasSecretKeyMaterial);
        Assert.False(c.Primary.StateAt(DateTimeOffset.UtcNow.AddSeconds(5)).IsValid);
        Assert.Equal(41, Sop(Sop(gen.Out, "extract-cert").Out, "revoke-key").Code);
    }

    [Fact]
    public void CertifyValidateAndMerge()
    {
        const string uid = "Alice <alice@example.org>";
        Result alice = Sop([], "generate-key", uid);
        Result bob = Sop([], "generate-key", "Bob <bob@example.org>");
        string bobKey = Scratch("bob.key", bob.Out);
        string bobCert = Scratch("bob.cert", Sop(bob.Out, "extract-cert").Out);
        Result aliceCert = Sop(alice.Out, "extract-cert");

        Assert.Equal(107, Sop(aliceCert.Out, "validate-userid", uid, bobCert).Code);
        Assert.Equal(19, Sop(aliceCert.Out, "certify-userid", bobKey).Code);
        Assert.Equal(107, Sop(aliceCert.Out, "certify-userid", "--userid=Nobody", bobKey).Code);

        Result certified = Sop(aliceCert.Out, "certify-userid", "--userid=" + uid, bobKey);
        Assert.Equal(0, certified.Code);
        Assert.Equal(0, Sop(certified.Out, "validate-userid", uid, bobCert).Code);
        Assert.Equal(0, Sop(certified.Out, "validate-userid", "--addr-spec-only", "alice@example.org", bobCert).Code);
        Assert.Equal(107, Sop(certified.Out, "validate-userid", uid, Scratch("other.cert", Sop(Sop([], "generate-key", "X").Out, "extract-cert").Out)).Code);
        Assert.Equal(107, Sop(certified.Out, "validate-userid", "--validate-at=2001-01-01T00:00:00Z", uid, bobCert).Code);

        // Absorbing the certification into the plain certificate, and into the secret key.
        Result merged = Sop(aliceCert.Out, "merge-certs", Scratch("certified.cert", certified.Out));
        Assert.Equal(0, merged.Code);
        Assert.Equal(0, Sop(merged.Out, "validate-userid", uid, bobCert).Code);
        Assert.Equal(19, Sop(aliceCert.Out, "merge-certs").Code);
        Result updated = Sop(alice.Out, "update-key", "--merge-certs=" + Scratch("c2.cert", certified.Out));
        Assert.Equal(0, updated.Code);
        Assert.StartsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----", Text(updated), StringComparison.Ordinal);
        Assert.Equal(0, Sop(Sop(updated.Out, "extract-cert").Out, "validate-userid", uid, bobCert).Code);

        Result unself = Sop(aliceCert.Out, "certify-userid", "--no-require-self-sig", "--userid=Extra Name", bobKey);
        Assert.Equal(0, unself.Code);
        Assert.Contains("Extra Name", PgpCertificate.Parse(unself.Out).UserIds);
    }

    [Fact]
    public void UpdateKeyKeepsTheFingerprintAndRefreshesTheKey()
    {
        Result gen = Sop([], "generate-key", "--signing-only", "U");
        Result upd = Sop(gen.Out, "update-key");
        Assert.Equal(0, upd.Code);
        PgpCertificate before = PgpCertificate.Parse(gen.Out);
        PgpCertificate after = PgpCertificate.Parse(upd.Out);
        Assert.Equal(before.Fingerprint, after.Fingerprint);
        Assert.Equal(2, after.Keys.Count);
        Assert.Single(PgpCertificate.Parse(Sop(gen.Out, "update-key", "--signing-only").Out).Keys);
    }

    [Fact]
    public void SopvReportsItsSubset()
    {
        Result v = Sop([], "version", "--sopv");
        Assert.Equal(0, v.Code);
        Assert.Equal("1.2\n", Text(v));
        using var inStream = new MemoryStream();
        using var outStream = new MemoryStream();
        Assert.Equal(69, SopApp.Run(["generate-key"], new SopIo(inStream, outStream, new StringWriter(), _ => null), sopvOnly: true));
        Assert.Equal(0, SopApp.Run(["version", "--sopv"], new SopIo(inStream, outStream, new StringWriter(), _ => null), sopvOnly: true));
    }
}
