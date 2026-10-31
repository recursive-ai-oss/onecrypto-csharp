using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;

namespace OneCrypto.Tests.Cms;

/// <summary>Two-way checks of SignedData against the openssl command-line program, used as a compiled black box. Skipped when it is not installed.</summary>
public class OpenSslSignedDataTests
{
    private static readonly byte[] Content = RandomNumberGenerator.GetBytes(4000);

    internal static string Dir(string name)
    {
        string d = Path.Combine(Environment.GetEnvironmentVariable("TMPDIR") ?? Path.GetTempPath(), "onecrypto-cms", name);
        Directory.CreateDirectory(d);
        return d;
    }

    internal static void Ok((int Code, string Output) r, string what) => Assert.True(r.Code == 0, what + ": " + r.Output);

    internal static bool OpenSslCan(SigKind k) => k switch
    {
        SigKind.Ed448 => OpenSslTool.Has("ED448"),
        SigKind.MlDsa65 => OpenSslTool.Has("ML-DSA-65") && CmsKeys.IsAvailable(k),
        _ => true,
    };

    public static IEnumerable<object[]> Matrix()
    {
        foreach (SigKind kind in Enum.GetValues<SigKind>())
        {
            foreach (bool attrs in new[] { true, false })
            {
                foreach (bool detached in new[] { true, false })
                {
                    yield return [kind, attrs, detached];
                }
            }
        }
    }

    [Theory]
    [MemberData(nameof(Matrix))]
    public void OpenSslVerifiesWhatWeSign(SigKind kind, bool attrs, bool detached)
    {
        OpenSslTool.RequireOrSkip();
        Assert.SkipUnless(OpenSslCan(kind) && CmsKeys.IsAvailable(kind), "unavailable here");
        // openssl cms cannot check an EdDSA or ML-DSA signature made over the content itself (no signed attributes).
        Assert.SkipUnless(attrs || kind is not (SigKind.Ed25519 or SigKind.Ed448 or SigKind.MlDsa65), "openssl cannot verify this form");
        SignerKit k = CmsKeys.Get(kind);
        string dir = Dir($"ours-{kind}-{attrs}-{detached}");
        SignedData sd = SignedData.Create(Content, [k.Spec(b => b.SignedAttributes = attrs)], new SignedDataOptions { Detached = detached });
        File.WriteAllBytes(Path.Combine(dir, "msg.der"), sd.Encoded.ToArray());
        File.WriteAllBytes(Path.Combine(dir, "content.bin"), Content);
        string[] args = ["cms", "-verify", "-inform", "DER", "-in", Path.Combine(dir, "msg.der"), "-noverify", "-binary", "-out", Path.Combine(dir, "out.bin")];
        Ok(OpenSslTool.Run(detached ? [.. args, "-content", Path.Combine(dir, "content.bin")] : [.. args]), "openssl cms -verify");
        Assert.Equal(Content, File.ReadAllBytes(Path.Combine(dir, "out.bin")));

        // The same message with one signature bit changed is refused.
        byte[] bad = sd.Encoded.ToArray();
        int at = bad.AsSpan().LastIndexOf(sd.Signers[0].Signature.Span);
        bad[at + 6] ^= 0x04;
        File.WriteAllBytes(Path.Combine(dir, "bad.der"), bad);
        string[] badArgs = ["cms", "-verify", "-inform", "DER", "-in", Path.Combine(dir, "bad.der"), "-noverify", "-binary", "-out", Path.Combine(dir, "bad.out")];
        Assert.NotEqual(0, OpenSslTool.Run(detached ? [.. badArgs, "-content", Path.Combine(dir, "content.bin")] : [.. badArgs]).Code);
    }

    [Theory]
    [MemberData(nameof(Matrix))]
    public void WeVerifyWhatOpenSslSigns(SigKind kind, bool attrs, bool detached)
    {
        OpenSslTool.RequireOrSkip();
        Assert.SkipUnless(OpenSslCan(kind) && CmsKeys.IsAvailable(kind), "unavailable here");
        SignerKit k = CmsKeys.Get(kind);
        string dir = Dir($"theirs-{kind}-{attrs}-{detached}");
        File.WriteAllText(Path.Combine(dir, "cert.pem"), k.Certificate.ToPem());
        File.WriteAllText(Path.Combine(dir, "key.pem"), k.Pkcs8Pem);
        File.WriteAllBytes(Path.Combine(dir, "content.bin"), Content);
        var args = new List<string> { "cms", "-sign", "-binary", "-outform", "DER", "-in", Path.Combine(dir, "content.bin"), "-signer", Path.Combine(dir, "cert.pem"), "-inkey", Path.Combine(dir, "key.pem"), "-out", Path.Combine(dir, "msg.der") };
        if (!detached)
        {
            args.Add("-nodetach");
        }

        if (!attrs)
        {
            args.Add("-noattr");
        }

        // These algorithms name no default digest in openssl; RFC 8419 §3.1 and RFC 9882 §3 give SHA-512 and SHAKE256.
        if (kind is SigKind.Ed25519 or SigKind.MlDsa65)
        {
            args.AddRange(["-md", "sha512"]);
        }
        else if (kind == SigKind.Ed448)
        {
            args.AddRange(["-md", "shake256"]);
        }

        if (kind == SigKind.RsaPss)
        {
            args.AddRange(["-keyopt", "rsa_padding_mode:pss"]);
        }

        (int code, string output) = OpenSslTool.Run([.. args]);
        Assert.SkipUnless(code == 0, "openssl could not make this message: " + output);
        SignedData sd = SignedData.Parse(File.ReadAllBytes(Path.Combine(dir, "msg.der")));
        SignedDataReport r = detached ? sd.Verify(Content) : sd.Verify();
        Assert.True(r.IsValid, string.Join(" | ", r.Signers[0].Checks.Where(static c => c.Status != CmsCheckStatus.Passed).Select(static c => $"{c.Rule}:{c.Status}:{c.Reason}")));
        if (!detached)
        {
            Assert.Equal(Content, sd.EncapsulatedContent.ToArray());
        }
    }

    [Fact]
    public void TwoSignersTwoWays()
    {
        OpenSslTool.RequireOrSkip();
        SignerKit a = CmsKeys.Get(SigKind.Rsa), b = CmsKeys.Get(SigKind.P256);
        string dir = Dir("two");
        File.WriteAllBytes(Path.Combine(dir, "content.bin"), Content);
        SignedData ours = SignedData.Create(Content, [a.Spec(), b.Spec()], new SignedDataOptions { Detached = true });
        File.WriteAllBytes(Path.Combine(dir, "ours.der"), ours.Encoded.ToArray());
        File.WriteAllText(Path.Combine(dir, "a.pem"), a.Certificate.ToPem());
        File.WriteAllText(Path.Combine(dir, "b.pem"), b.Certificate.ToPem());
        File.WriteAllText(Path.Combine(dir, "a.key"), a.Pkcs8Pem);
        File.WriteAllText(Path.Combine(dir, "b.key"), b.Pkcs8Pem);
        Ok(OpenSslTool.Run("cms", "-verify", "-inform", "DER", "-in", Path.Combine(dir, "ours.der"), "-content", Path.Combine(dir, "content.bin"), "-noverify", "-binary", "-out", Path.Combine(dir, "o.bin")), "openssl verifies two signers");
        Ok(OpenSslTool.Run("cms", "-sign", "-binary", "-outform", "DER", "-in", Path.Combine(dir, "content.bin"), "-signer", Path.Combine(dir, "a.pem"), "-inkey", Path.Combine(dir, "a.key"), "-signer", Path.Combine(dir, "b.pem"), "-inkey", Path.Combine(dir, "b.key"), "-out", Path.Combine(dir, "theirs.der")), "openssl signs two");
        SignedData theirs = SignedData.Parse(File.ReadAllBytes(Path.Combine(dir, "theirs.der")));
        Assert.Equal(2, theirs.Signers.Count);
        Assert.True(theirs.Verify(Content).IsValid);
    }

    [Fact]
    public void SubjectKeyIdentifierSignerAndCountersignatureInterop()
    {
        OpenSslTool.RequireOrSkip();
        SignerKit a = CmsKeys.Get(SigKind.P384);
        string dir = Dir("ski");
        File.WriteAllBytes(Path.Combine(dir, "content.bin"), Content);
        SignedData ours = SignedData.Create(Content, [a.Spec(x => x.Identifier = CmsIdentifierKind.SubjectKeyIdentifier)], new SignedDataOptions { Detached = true });
        File.WriteAllBytes(Path.Combine(dir, "ours.der"), ours.Encoded.ToArray());
        Ok(OpenSslTool.Run("cms", "-verify", "-inform", "DER", "-in", Path.Combine(dir, "ours.der"), "-content", Path.Combine(dir, "content.bin"), "-noverify", "-binary", "-out", Path.Combine(dir, "o.bin")), "ski");

        // A countersigned message still verifies in openssl (it ignores the unsigned attribute) and we check the countersignature.
        SignerKit c = CmsKeys.Get(SigKind.Rsa);
        SignedData counter = ours.WithUnsignedAttribute(0, SignedData.CreateCountersignature(ours.Signers[0], c.Spec()), [c.Certificate]);
        File.WriteAllBytes(Path.Combine(dir, "counter.der"), counter.Encoded.ToArray());
        Ok(OpenSslTool.Run("cms", "-verify", "-inform", "DER", "-in", Path.Combine(dir, "counter.der"), "-content", Path.Combine(dir, "content.bin"), "-noverify", "-binary", "-out", Path.Combine(dir, "o2.bin")), "countersigned");
        Assert.True(SignedData.Parse(counter.Encoded).Verify(Content).IsValid);
    }

    [Fact]
    public void OpenSslCmsDumpReadsOurStructure()
    {
        OpenSslTool.RequireOrSkip();
        string dir = Dir("dump");
        SignedData sd = SignedData.Create(Content, [CmsKeys.Get(SigKind.Rsa).Spec(), CmsKeys.Get(SigKind.P256).Spec()]);
        File.WriteAllBytes(Path.Combine(dir, "m.der"), sd.Encoded.ToArray());
        (int code, string text) = OpenSslTool.Run("cms", "-cmsout", "-inform", "DER", "-in", Path.Combine(dir, "m.der"), "-print");
        Assert.True(code == 0, text);
        Assert.Contains("signingCertificateV2", text, StringComparison.OrdinalIgnoreCase);
    }
}
