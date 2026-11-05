using System.Linq;
using System.Security.Cryptography;
using System.Text;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace OneCrypto.Tests.Cms;

/// <summary>
/// EC key agreement against Windows' CMS encoder (messages made on Windows are committed in <c>testdata/cms/windows-ecdh</c>) and against
/// openssl across curves and key-wrap sizes. Windows writes explicit NULL parameters on the key-wrap and originator-key algorithm identifiers and
/// computes the RFC 5753 §7.2 SharedInfo from the message's bytes, so the writer must emit the same NULL and the reader must accept it.
/// </summary>
public class EcKeyAgreementInteropTests
{
    private static readonly string Dir = Path.Combine(TestFiles.TestData, "cms", "windows-ecdh");

    private static readonly string[] WindowsNames = ["windows-sha1-a256", "windows-sha256-a256", "windows-sha1-a256-ukm", "windows-sha1-a256-ski"];

    private static readonly string[] Ciphers = [CmsOids.Aes128Cbc, CmsOids.Aes192Cbc, CmsOids.Aes256Cbc];

    private static readonly (string Oid, string Arg)[] CipherArgs = [(CmsOids.Aes128Cbc, "-aes-128-cbc"), (CmsOids.Aes192Cbc, "-aes-192-cbc"), (CmsOids.Aes256Cbc, "-aes-256-cbc")];

    public static IEnumerable<object[]> WindowsMessages() => WindowsNames.Select(static n => new object[] { n });

    private static byte[] ReadEml(string name)
    {
        string text = File.ReadAllText(Path.Combine(Dir, name + ".eml"));
        int blank = text.IndexOf("\n\n", StringComparison.Ordinal);
        int blankCrLf = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        string body = blankCrLf >= 0 && (blank < 0 || blankCrLf < blank) ? text[(blankCrLf + 4)..] : text[(blank + 2)..];
        return Convert.FromBase64String(string.Concat(body.Where(static ch => !char.IsWhiteSpace(ch))));
    }

    [Theory]
    [MemberData(nameof(WindowsMessages))]
    public void WeDecryptWhatWindowsEncrypts(string name)
    {
        Certificate cert = Certificate.FromPem(File.ReadAllText(Path.Combine(Dir, "cert.pem")));
        using var ec = ECDiffieHellman.Create();
        ec.ImportFromPem(File.ReadAllText(Path.Combine(Dir, "key.pem")));
        using CmsDecryptionKey key = CmsDecryptionKey.FromECDiffieHellman(ec, cert);
        byte[] plain = EnvelopedData.Parse(ReadEml(name)).Decrypt(key);
        Assert.Contains(File.ReadAllText(Path.Combine(Dir, "expected.txt")).Trim(), Encoding.ASCII.GetString(plain));
    }

    private static readonly byte[][] WrapOids =
    [
        DerOid(CmsOids.Aes128Wrap), DerOid(CmsOids.Aes192Wrap), DerOid(CmsOids.Aes256Wrap),
    ];

    private static byte[] DerOid(string oid) => RecursiveAI.OneCrypto.Asn1.DerWriter.Oid(oid);

    /// <summary>Whether the first key-wrap identifier in the message is followed by an explicit NULL.</summary>
    private static bool WrapHasNull(byte[] msg)
    {
        foreach (byte[] oid in WrapOids)
        {
            int at = msg.AsSpan().IndexOf(oid);
            if (at >= 0)
            {
                int next = at + oid.Length;
                return msg[next] == 0x05 && msg[next + 1] == 0x00;
            }
        }

        throw new InvalidOperationException("no key-wrap identifier in the message");
    }

    [Theory]
    [InlineData(RecipKind.P256)]
    [InlineData(RecipKind.P384)]
    [InlineData(RecipKind.P521)]
    [InlineData(RecipKind.X25519)]
    [InlineData(RecipKind.X448)]
    public void WrapIdentifierCarriesNullOnlyForEc(RecipKind kind)
    {
        RecipientKit kit = RecipientKit.Get(kind);
        foreach (string cipher in Ciphers)
        {
            byte[] msg = EnvelopedData.Create("hi"u8, [CmsRecipient.KeyAgreement(kit.Certificate)], new CmsEncryptOptions { ContentEncryption = cipher }).Encoded.ToArray();
            Assert.Equal(kind is RecipKind.P256 or RecipKind.P384 or RecipKind.P521, WrapHasNull(msg));
            using CmsDecryptionKey key = kit.Key();
            Assert.Equal("hi"u8.ToArray(), EnvelopedData.Parse(msg).Decrypt(key));
        }
    }

    [Theory]
    [InlineData(RecipKind.P256)]
    [InlineData(RecipKind.P384)]
    [InlineData(RecipKind.P521)]
    public void OpenSslTwoWayAcrossWrapSizes(RecipKind kind)
    {
        OpenSslTool.RequireOrSkip();
        RecipientKit kit = RecipientKit.Get(kind);
        string dir = OpenSslSignedDataTests.Dir("kari-" + kind);
        File.WriteAllText(Path.Combine(dir, "cert.pem"), kit.Certificate.ToPem());
        File.WriteAllText(Path.Combine(dir, "key.pem"), kit.Pkcs8Pem);
        byte[] content = RandomNumberGenerator.GetBytes(3000);
        File.WriteAllBytes(Path.Combine(dir, "pt.bin"), content);
        string kdf = kind == RecipKind.P256 ? "sha256" : kind == RecipKind.P384 ? "sha384" : "sha512";
        foreach ((string cipher, string ossl) in CipherArgs)
        {
            string tag = ossl.Trim('-');

            // openssl -> ours
            string msgPath = Path.Combine(dir, tag + "-o.der");
            (int code, string output) = OpenSslTool.Run(["cms", "-encrypt", "-binary", "-in", Path.Combine(dir, "pt.bin"), "-outform", "DER", "-out", msgPath,
                "-recip", Path.Combine(dir, "cert.pem"), ossl, "-keyopt", "ecdh_kdf_md:" + kdf]);
            Assert.True(code == 0, output);
            using (CmsDecryptionKey key = kit.Key())
            {
                Assert.Equal(content, EnvelopedData.Parse(File.ReadAllBytes(msgPath)).Decrypt(key));
            }

            // ours -> openssl
            string ours = Path.Combine(dir, tag + "-u.der");
            File.WriteAllBytes(ours, EnvelopedData.Create(content, [CmsRecipient.KeyAgreement(kit.Certificate)], new CmsEncryptOptions { ContentEncryption = cipher }).Encoded.ToArray());
            string outPath = Path.Combine(dir, tag + "-out.bin");
            (code, output) = OpenSslTool.Run(["cms", "-decrypt", "-binary", "-inform", "DER", "-in", ours, "-out", outPath, "-inkey", Path.Combine(dir, "key.pem"), "-recip", Path.Combine(dir, "cert.pem")]);
            Assert.True(code == 0, output);
            Assert.Equal(content, File.ReadAllBytes(outPath));
        }
    }
}
