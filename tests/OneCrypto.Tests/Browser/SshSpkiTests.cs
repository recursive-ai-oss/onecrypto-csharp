using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Wire.Ssh;

namespace OneCrypto.Tests.Browser;

/// <summary>
/// An OpenSSH public key becomes a SubjectPublicKeyInfo from its numbers, without the platform's RSA or ECDSA, so that it also works
/// where the platform has neither. The encoding must be the one the platform itself writes for the same key.
/// </summary>
public class SshSpkiTests
{
    [Theory]
    [InlineData("ssh-rsa.pub")]
    [InlineData("ssh-ecdsa.pub")]
    public void TheEncodingMatchesTheOneThePlatformWrites(string file)
    {
        SshPublicKey key = SshPublicKey.ParseAuthorizedKey(File.ReadAllText(Path.Combine(TestFiles.TestData, "browser", file)));
        PublicKeyInfo ours = key.ToPublicKeyInfo();
        byte[] platform;
        if (key.Type == SshKeyType.Rsa)
        {
            using RSA rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(ours.Encoded.Span, out _);
            platform = rsa.ExportSubjectPublicKeyInfo();
        }
        else
        {
            using ECDsa ec = ECDsa.Create();
            ec.ImportSubjectPublicKeyInfo(ours.Encoded.Span, out _);
            platform = ec.ExportSubjectPublicKeyInfo();
        }

        Assert.Equal(platform, ours.Encoded.ToArray());
    }

    [Fact]
    public void AnRsaKeyWithALeadingZeroInItsSshModulusIsNotPaddedTwice()
    {
        // The SSH encoding of a 2048-bit modulus starts with a zero byte (a multi-precision integer is signed); the SPKI integer must not repeat it.
        SshPublicKey key = SshPublicKey.ParseAuthorizedKey(File.ReadAllText(Path.Combine(TestFiles.TestData, "browser", "ssh-rsa.pub")));
        Assert.Equal(2048, key.ToPublicKeyInfo().KeySizeBits);
    }
}
