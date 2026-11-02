using System.Diagnostics;
using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.Online.Csc;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace OneCrypto.Online.Tests.Csc;

/// <summary>What the remote key is for: CMS signatures an independent verifier accepts, and signatures prepared in one process and made in another.</summary>
public class CscInteropTests
{
    private static readonly byte[] Doc = "a document signed by a key that never leaves the signing service"u8.ToArray();

    private static string Dir(string name)
    {
        string d = Path.Combine(Environment.GetEnvironmentVariable("TMPDIR") ?? Path.GetTempPath(), "onecrypto-csc", name);
        Directory.CreateDirectory(d);
        return d;
    }

    [Theory]
    [InlineData("rsa", "rsa-pkcs1-sha256", 1)]
    [InlineData("rsa", "rsa-pkcs1-sha384", 2)]
    [InlineData("rsa", "rsa-pss-sha256", 2)]
    [InlineData("p256", "ecdsa-sha256", 1)]
    [InlineData("p384", "ecdsa-sha384", 2)]
    public async Task ACmsSignatureMadeThroughTheServiceVerifiesInOpenSsl(string kind, string specName, int scal)
    {
        OpenSslTool.RequireOrSkip();
        var rig = new CscRig();
        using CscSigningKey key = await rig.Open(CscRig.Credential("C-" + specName, kind, scal, ecdsaDer: specName.EndsWith("384", StringComparison.Ordinal)));
        SignatureSpec spec = CscRig.Spec(specName);

        SignedData cms = SignedData.Create(Doc, [new CmsSignerSpec { Certificate = key.Certificate, Key = key, SignatureSpec = spec }]);

        Assert.True(cms.Verify().IsValid);
        // The service signed exactly one digest, the one of the signed attributes: the document itself never went over the wire.
        Assert.Single(rig.Server.Calls, c => c.Path == "signatures/signHash");
        Assert.DoesNotContain(rig.Server.Calls, c => c.Body.Contains(Convert.ToBase64String(Doc), StringComparison.Ordinal));

        string dir = Dir("cms-" + specName + scal);
        File.WriteAllBytes(Path.Combine(dir, "m.der"), cms.Encoded.ToArray());
        (int code, string output) = OpenSslTool.RunIn(dir, "cms", "-verify", "-inform", "DER", "-in", "m.der", "-noverify", "-binary", "-out", "o.bin");
        Assert.True(code == 0, "openssl cms -verify: " + output);
        Assert.Equal(Doc, File.ReadAllBytes(Path.Combine(dir, "o.bin")));

        // And against the chain the service gave: the signer certificate, its intermediate and the root.
        File.WriteAllText(Path.Combine(dir, "root.pem"), key.Credential.Certificates.Count == 3 ? Certificate.Parse(key.Credential.Certificates[2]).ToPem() : string.Empty);
        File.WriteAllText(Path.Combine(dir, "inter.pem"), Certificate.Parse(key.Credential.Certificates[1]).ToPem());
        (int chained, string chainOut) = OpenSslTool.RunIn(dir, "cms", "-verify", "-inform", "DER", "-in", "m.der", "-CAfile", "root.pem", "-certfile", "inter.pem", "-purpose", "smimesign", "-no_check_time", "-binary", "-out", "o2.bin");
        Assert.True(chained == 0, "openssl cms -verify with the chain: " + chainOut);
    }

    [Fact]
    public async Task APreparedSignatureCompletesWithAnAnswerFromTheService()
    {
        var rig = new CscRig();
        using CscSigningKey key = await rig.Open(CscRig.Credential("C1", "rsa", scal: 2));
        SignatureSpec spec = SignatureSpec.RsaPss(HashAlgorithmName.SHA256);

        PreparedSignature prepared = PreparedSignature.Prepare(key.PublicKey, spec, Doc, CryptoPolicy.Standard, World.Now);
        PreparedSignature again = PreparedSignature.Decode(prepared.Encode());
        byte[] sig = await key.SignDigestAsync(again.ToSign, again.Spec);

        Assert.Equal(sig, again.Complete(sig));
        byte[] viaState = await again.SignWithAsync(key);
        Assert.True(spec.Verify(key.PublicKey, Doc, viaState).IsValid);
    }

    [Fact]
    public async Task APreparedSignatureCrossesProcessesAndCompletesAfterwards()
    {
        string dotnet = Environment.GetEnvironmentVariable("DOTNET_ROOT") is { } root && File.Exists(Path.Combine(root, "dotnet")) ? Path.Combine(root, "dotnet") : "dotnet";
        var rig = new CscRig();
        CscTestCredential credential = CscRig.Credential("C1", "p256", scal: 2, pin: "246810");
        rig.Server.Add(credential);

        // The service as another process sees it: real HTTP on the loopback interface, answering from the same test server.
        using var http = new TestServer((line, headers, body) =>
        {
            string path = line.Split(' ')[1]["/csc/v2/".Length..];
            (int status, byte[] json) = rig.Server.Handle(path, headers.GetValueOrDefault("Authorization"), body);
            return TestServer.Response(status, status == 200 ? "OK" : "Bad Request", json, "Content-Type: application/json");
        });

        SignatureSpec spec = SignatureSpec.Ecdsa(HashAlgorithmName.SHA256);
        PreparedSignature prepared = PreparedSignature.Prepare(credential.Key.PublicKey, spec, Doc, CryptoPolicy.Standard, World.Now, "csc.test");
        string dir = Dir("two-phase");
        string statePath = Path.Combine(dir, "state.der"), sigPath = Path.Combine(dir, "sig.bin"), tokenPath = Path.Combine(dir, "token.txt");
        File.WriteAllBytes(statePath, prepared.Encode());
        File.WriteAllText(tokenPath, rig.Token);
        File.Delete(sigPath);
        string signer = Directory.GetFiles(AppContext.BaseDirectory, "*CscSigner.dll").Single();

        var psi = new ProcessStartInfo(dotnet) { RedirectStandardError = true, RedirectStandardOutput = true };
        foreach (string a in new[] { signer, $"http://127.0.0.1:{http.Port}/csc/v2/", tokenPath, "C1", "246810", statePath, sigPath })
        {
            psi.ArgumentList.Add(a);
        }

        using Process p = Process.Start(psi)!;
        Task<string> err = p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync();
        Assert.True(p.ExitCode == 0, "signer process failed: " + await err);

        // Days later, somewhere else: only the bytes of the state and the signature are needed.
        PreparedSignature restored = PreparedSignature.Decode(File.ReadAllBytes(statePath));
        byte[] completed = restored.Complete(File.ReadAllBytes(sigPath));
        Assert.True(spec.Verify(credential.Key.PublicKey, Doc, completed).IsValid);
        Assert.Contains(rig.Server.Calls, c => c.Path == "signatures/signHash");
        Assert.DoesNotContain(rig.Server.Calls, c => c.Body.Contains(Convert.ToBase64String(Doc), StringComparison.Ordinal));
        Assert.DoesNotContain("246810", await err, StringComparison.Ordinal);

        // A signature over other data is refused at completion.
        PreparedSignature other = PreparedSignature.Prepare(credential.Key.PublicKey, spec, "other"u8, CryptoPolicy.Standard, World.Now, "csc.test");
        Assert.Throws<InvalidSignatureException>(() => other.Complete(File.ReadAllBytes(sigPath)));
    }
}
