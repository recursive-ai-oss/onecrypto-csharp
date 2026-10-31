using System.Linq;
using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace OneCrypto.Tests.Cms;

/// <summary>
/// Two-way checks of EnvelopedData, AuthEnvelopedData and CompressedData against the openssl command-line program. Each case names the
/// recipient kind and the options; openssl is the oracle in both directions. Where openssl does not support a form the case says so and
/// only checks that openssl refuses it, so a later openssl that adds it turns the case into a real comparison.
/// </summary>
public class OpenSslEnvelopedTests
{
    private static readonly byte[] Content = RandomNumberGenerator.GetBytes(5000);

    private static readonly byte[] KekBytes = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static readonly byte[] KekId = "kek-id-1"u8.ToArray();

    private sealed record Case(string Name, RecipKind? Kind, string[] OpensslEncryptArgs, Func<RecipientKit?, CmsRecipient> Recipient, bool Aead = false, bool OpensslSupports = true)
    {
        public override string ToString() => Name;
    }

    private static readonly string[] Cbc = ["-aes-256-cbc"];
    private static readonly string[] Gcm = ["-aes-256-gcm"];

    private static readonly Case[] All =
    [
            new("ktri-oaep-sha256", RecipKind.Rsa, [.. Cbc, "-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256", "-keyopt", "rsa_mgf1_md:sha256"], k => CmsRecipient.KeyTransport(k!.Certificate, KeyTransportScheme.OaepSha256)),
            new("ktri-oaep-sha1", RecipKind.Rsa, [.. Cbc, "-keyopt", "rsa_padding_mode:oaep"], k => CmsRecipient.KeyTransport(k!.Certificate, KeyTransportScheme.OaepSha1)),
            new("ktri-v15", RecipKind.Rsa, [.. Cbc], k => CmsRecipient.KeyTransport(k!.Certificate, KeyTransportScheme.Pkcs1V15)),
            new("kari-p256", RecipKind.P256, [.. Cbc, "-keyopt", "ecdh_kdf_md:sha256"], k => CmsRecipient.KeyAgreement(k!.Certificate)),
            new("kari-p384", RecipKind.P384, [.. Cbc, "-keyopt", "ecdh_kdf_md:sha256"], k => CmsRecipient.KeyAgreement(k!.Certificate)),
            new("kari-x25519", RecipKind.X25519, [.. Cbc], k => CmsRecipient.KeyAgreement(k!.Certificate), OpensslSupports: false),
            new("kari-x448", RecipKind.X448, [.. Cbc], k => CmsRecipient.KeyAgreement(k!.Certificate), OpensslSupports: false),
            new("kemri-mlkem768", RecipKind.MlKem768, [.. Cbc], k => CmsRecipient.Kem(k!.Certificate), OpensslSupports: false),
            new("kekri", null, [.. Cbc, "-secretkey", Convert.ToHexString(KekBytes), "-secretkeyid", Convert.ToHexString(KekId)], _ => CmsRecipient.KeyEncryptionKey(KekBytes, KekId)),
            new("pwri", null, [.. Cbc, "-pwri_password", "correct horse"], _ => CmsRecipient.Password("correct horse", 10000)),
            new("authenv-ktri-gcm", RecipKind.Rsa, [.. Gcm, "-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256", "-keyopt", "rsa_mgf1_md:sha256"], k => CmsRecipient.KeyTransport(k!.Certificate), Aead: true),
            new("authenv-kari-gcm", RecipKind.P256, [.. Gcm, "-keyopt", "ecdh_kdf_md:sha256"], k => CmsRecipient.KeyAgreement(k!.Certificate), Aead: true),
    ];

    public static IEnumerable<object[]> Cases() => All.Select(static c => new object[] { c.Name });

    private static string Dir(string name) => OpenSslSignedDataTests.Dir("env-" + name);

    private static string[] RecipientArgs(Case c, RecipientKit? kit, string dir, bool decrypt)
    {
        if (kit is null)
        {
            return [];
        }

        File.WriteAllText(Path.Combine(dir, "cert.pem"), kit.Certificate.ToPem());
        File.WriteAllText(Path.Combine(dir, "key.pem"), kit.Pkcs8Pem);
        return decrypt ? ["-inkey", Path.Combine(dir, "key.pem"), "-recip", Path.Combine(dir, "cert.pem")] : ["-recip", Path.Combine(dir, "cert.pem")];
    }

    private static string[] SecretArgs(Case c) => c.Name switch
    {
        "kekri" => ["-secretkey", Convert.ToHexString(KekBytes), "-secretkeyid", Convert.ToHexString(KekId)],
        "pwri" => ["-pwri_password", "correct horse"],
        _ => [],
    };

    private static CmsDecryptionKey OurKey(Case c, RecipientKit? kit) => c.Name switch
    {
        "kekri" => CmsDecryptionKey.FromKeyEncryptionKey(KekBytes, KekId),
        "pwri" => CmsDecryptionKey.FromPassword("correct horse"),
        _ => kit!.Key(),
    };

    private static byte[] OurDecrypt(Case c, byte[] msg, CmsDecryptionKey key) =>
        c.Aead ? AuthEnvelopedData.Parse(msg).Decrypt(key) : EnvelopedData.Parse(msg).Decrypt(key);

    [Theory]
    [MemberData(nameof(Cases))]
    public void WeDecryptWhatOpenSslEncrypts(string name)
    {
        Case c = All.Single(x => x.Name == name);
        OpenSslTool.RequireOrSkip();
        RecipientKit? kit = c.Kind is { } kind ? RecipientKit.Get(kind) : null;
        Assert.SkipUnless(kit is null || RecipientKit.IsAvailable(c.Kind!.Value), "unavailable here");
        string dir = Dir("o2u-" + c.Name);
        File.WriteAllBytes(Path.Combine(dir, "pt.bin"), Content);
        string msg = Path.Combine(dir, "msg.der");
        string[] args = ["cms", "-encrypt", "-binary", "-in", Path.Combine(dir, "pt.bin"), "-outform", "DER", "-out", msg, .. RecipientArgs(c, kit, dir, false), .. c.OpensslEncryptArgs];
        (int code, string output) = OpenSslTool.Run(args);
        if (!c.OpensslSupports && code != 0)
        {
            Assert.Skip("openssl cannot make this form: " + output.Split('\n')[0]);
        }

        Assert.True(code == 0, output);
        using CmsDecryptionKey key = OurKey(c, kit);
        Assert.Equal(Content, OurDecrypt(c, File.ReadAllBytes(msg), key));
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void OpenSslDecryptsWhatWeEncrypt(string name)
    {
        Case c = All.Single(x => x.Name == name);
        OpenSslTool.RequireOrSkip();
        RecipientKit? kit = c.Kind is { } kind ? RecipientKit.Get(kind) : null;
        Assert.SkipUnless(kit is null || RecipientKit.IsAvailable(c.Kind!.Value), "unavailable here");
        string dir = Dir("u2o-" + c.Name);
        var options = new CmsEncryptOptions { AllowLegacy = true, ContentEncryption = c.Aead ? CmsOids.Aes256Gcm : CmsOids.Aes256Cbc };
        CmsRecipient r = c.Recipient(kit);
        byte[] msg = c.Aead ? AuthEnvelopedData.Create(Content, [r], options).Encoded.ToArray() : EnvelopedData.Create(Content, [r], options).Encoded.ToArray();
        string path = Path.Combine(dir, "msg.der");
        File.WriteAllBytes(path, msg);
        string[] args = ["cms", "-decrypt", "-binary", "-inform", "DER", "-in", path, "-out", Path.Combine(dir, "out.bin"), .. RecipientArgs(c, kit, dir, true), .. SecretArgs(c)];
        (int code, string output) = OpenSslTool.Run(args);
        if (!c.OpensslSupports && code != 0)
        {
            Assert.Skip("openssl cannot open this form: " + output.Split('\n')[0]);
        }

        Assert.True(code == 0, output);
        Assert.Equal(Content, File.ReadAllBytes(Path.Combine(dir, "out.bin")));

        // The same message with a ciphertext byte changed is refused when the content is authenticated.
        if (c.Aead)
        {
            byte[] bad = (byte[])msg.Clone();
            bad[bad.AsSpan().IndexOf(AuthEnvelopedData.Parse(msg).EncryptedContent.Span) + 10] ^= 1;
            File.WriteAllBytes(path, bad);
            Assert.NotEqual(0, OpenSslTool.Run(args).Code);
        }
    }

    [Fact]
    public void CompressedDataTwoWay()
    {
        OpenSslTool.RequireOrSkip();
        string dir = Dir("compress");
        File.WriteAllBytes(Path.Combine(dir, "pt.bin"), Content);
        string msg = Path.Combine(dir, "o.der");
        (int code, string output) = OpenSslTool.Run("cms", "-compress", "-binary", "-in", Path.Combine(dir, "pt.bin"), "-outform", "DER", "-out", msg);
        if (code != 0)
        {
            Assert.Skip("this openssl was built without zlib: " + output.Split('\n').LastOrDefault(static l => l.Contains("error", StringComparison.Ordinal)));
        }

        Assert.Equal(Content, CompressedData.Parse(File.ReadAllBytes(msg)).Decompress());
        string ours = Path.Combine(dir, "u.der");
        File.WriteAllBytes(ours, CompressedData.Create(Content).Encoded.ToArray());
        Assert.Equal(0, OpenSslTool.Run("cms", "-uncompress", "-binary", "-inform", "DER", "-in", ours, "-out", Path.Combine(dir, "u.out")).Code);
        Assert.Equal(Content, File.ReadAllBytes(Path.Combine(dir, "u.out")));
    }

    [Fact]
    public void StreamedMessagesInteroperate()
    {
        OpenSslTool.RequireOrSkip();
        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        string dir = Dir("streamed");
        string key = Path.Combine(dir, "key.pem");
        string cert = Path.Combine(dir, "cert.pem");
        File.WriteAllText(key, kit.Pkcs8Pem);
        File.WriteAllText(cert, kit.Certificate.ToPem());
        string ours = Path.Combine(dir, "ours.der");
        using (FileStream fs = File.Create(ours))
        {
            EnvelopedData.EncryptStream(new MemoryStream(Content), fs, [CmsRecipient.KeyTransport(kit.Certificate)]);
        }

        Assert.Equal(0, OpenSslTool.Run("cms", "-decrypt", "-binary", "-inform", "DER", "-in", ours, "-inkey", key, "-recip", cert, "-out", Path.Combine(dir, "a.out")).Code);
        Assert.Equal(Content, File.ReadAllBytes(Path.Combine(dir, "a.out")));

        // openssl -stream writes indefinite-length BER; the stream reader takes it.
        string pt = Path.Combine(dir, "pt.bin");
        File.WriteAllBytes(pt, Content);
        string theirs = Path.Combine(dir, "theirs.der");
        Assert.Equal(0, OpenSslTool.Run("cms", "-encrypt", "-stream", "-binary", "-in", pt, "-outform", "DER", "-out", theirs, "-aes-256-cbc", cert).Code);
        var plain = new MemoryStream();
        using (CmsDecryptionKey k = kit.Key())
        using (FileStream fs = File.OpenRead(theirs))
        {
            EnvelopedData.DecryptStream(fs, plain, k);
        }

        Assert.Equal(Content, plain.ToArray());

        SignerKit sk = CmsKeys.Get(SigKind.P256);
        string signed = Path.Combine(dir, "signed.der");
        File.WriteAllText(Path.Combine(dir, "skey.pem"), sk.Pkcs8Pem);
        File.WriteAllText(Path.Combine(dir, "scert.pem"), sk.Certificate.ToPem());
        Assert.Equal(0, OpenSslTool.Run("cms", "-sign", "-stream", "-binary", "-in", pt, "-outform", "DER", "-out", signed, "-signer", Path.Combine(dir, "scert.pem"), "-inkey", Path.Combine(dir, "skey.pem")).Code);
        var seen = new MemoryStream();
        using (FileStream fs = File.OpenRead(signed))
        {
            Assert.True(SignedData.VerifyStream(fs, seen).IsValid);
        }

        Assert.Equal(Content, seen.ToArray());

        string oursSigned = Path.Combine(dir, "ours-signed.der");
        using (FileStream fs = File.Create(oursSigned))
        {
            SignedData.SignStream(new MemoryStream(Content), fs, [sk.Spec()]);
        }

        Assert.Equal(0, OpenSslTool.Run("cms", "-verify", "-binary", "-inform", "DER", "-in", oursSigned, "-noverify", "-out", Path.Combine(dir, "v.out")).Code);
        Assert.Equal(Content, File.ReadAllBytes(Path.Combine(dir, "v.out")));
    }
}
