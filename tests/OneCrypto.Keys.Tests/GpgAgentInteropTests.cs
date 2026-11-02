using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Keys.Agents;
using RecursiveAI.OneCrypto.OpenPgp;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Keys.Tests;

/// <summary>
/// What gpg-agent keys are for: OpenPGP and CMS signatures made through the agent that gpg, sqop and openssl accept, and messages encrypted to the keys that
/// decrypt through the agent. The two-phase tests do the signing in a separate process.
/// </summary>
public class GpgAgentInteropTests : IClassFixture<GpgAgentFixture>
{
    private static readonly string OpenSsl = Environment.GetEnvironmentVariable("ONECRYPTO_OPENSSL") ?? "openssl";

    private readonly GpgAgentFixture _f;
    private readonly string _work;

    public GpgAgentInteropTests(GpgAgentFixture fixture)
    {
        _f = fixture;
        fixture.RequireGpg();
        _work = Tools.ShortTemp("io");
    }

    private GpgAgentClient Client() => new(new GpgAgentOptions { HomeDirectory = _f.Home });

    private PgpCertificate Cert(string name) => PgpCertificate.Parse(_f.GpgRun(null, "--export", _f.Key(name).Fingerprint).Out);

    private string Write(string name, byte[] bytes)
    {
        string p = Path.Combine(_work, name);
        File.WriteAllBytes(p, bytes);
        return p;
    }

    private static bool SqopAvailable(out string sqop)
    {
        sqop = Environment.GetEnvironmentVariable("ONECRYPTO_SQOP") ?? string.Empty;
        return File.Exists(sqop);
    }

    public static TheoryData<string> Keys => ["rsa", "p256", "ed25519"];

    // ---- OpenPGP signatures ----

    [Theory]
    [MemberData(nameof(Keys))]
    public void AnOpenPgpSignatureMadeThroughTheAgentVerifiesUnderGpgAndSqop(string name)
    {
        PgpCertificate cert = Cert(name);
        byte[] data = Encoding.UTF8.GetBytes("an OpenPGP document signed by a key that never left gpg-agent\n");
        using var ms = new MemoryStream(data);
        PgpPreparedSignature prepared = PgpPreparedSignature.PrepareDetached(cert.Primary, ms, DateTimeOffset.UtcNow);
        using GpgAgentKey key = Client().GetKey(_f.Key(name).SignGrip);
        var signer = (ISigningKey)key;
        byte[] raw = prepared.Input == SigningInput.Digest ? signer.SignDigest(prepared.ToSign.Span, prepared.Spec) : signer.Sign(prepared.ToSign.Span, prepared.Spec);
        byte[] armored = prepared.CompleteArmored(raw);

        string sig = Write("sig.asc", armored), doc = Write("doc.txt", data);
        (int code, byte[] _, string err) = _f.GpgRun(null, "--verify", sig, doc);
        Assert.True(code == 0, err);
        Assert.Contains("Good signature", err, StringComparison.Ordinal);

        if (SqopAvailable(out string sqop))
        {
            string certFile = Write("cert.asc", _f.GpgRun(null, "--export", "--armor", _f.Key(name).Fingerprint).Out);
            (int sc, byte[] so, string se) = Tools.Run(sqop, ["verify", sig, certFile], stdin: data);
            Assert.True(sc == 0, se + Tools.Text(so));
            Assert.Contains(_f.Key(name).Fingerprint[..16], Tools.Text(so).Replace(" ", string.Empty, StringComparison.Ordinal), StringComparison.OrdinalIgnoreCase);
        }
    }

    // ---- messages encrypted to the agent's keys ----

    [Theory]
    [MemberData(nameof(Keys))]
    public void AMessageGpgEncryptedToTheKeyDecryptsThroughTheAgent(string name)
    {
        byte[] plain = Encoding.UTF8.GetBytes("a secret for the key in the agent\n");
        (int ec, byte[] message, string ee) = _f.GpgRun(plain, "--armor", "--trust-model", "always", "--recipient", _f.Key(name).Fingerprint, "--encrypt");
        Assert.True(ec == 0, ee);

        PgpCertificate cert = Cert(name);
        PgpKey subkey = cert.Keys.Single(k => !k.IsPrimary);
        using GpgAgentKey agentKey = Client().GetKey(_f.Key(name).EncryptGrip);
        using PgpSecretKey external = PgpSecretKey.FromExternalKey(subkey, agentKey);
        using var input = new MemoryStream(message);
        using var output = new MemoryStream();
        PgpReadResult result = PgpMessageReader.Read(input, output, new PgpReadOptions { Now = DateTimeOffset.UtcNow, ExternalKeys = [external] });
        Assert.True(result.WasEncrypted);
        Assert.Equal(plain, output.ToArray());
    }

    [Fact]
    public void ADecryptionThatTheUserCancelsAtThePromptIsATypedRefusal()
    {
        // The locked key is RSA 2048; the cancel comes from the agent's pinentry, not from us.
        byte[] plain = [1, 2, 3];
        (int ec, byte[] message, string ee) = _f.GpgRun(plain, "--trust-model", "always", "--recipient", _f.Key("locked").Fingerprint, "--encrypt");
        Assert.True(ec == 0, ee);
        PgpCertificate cert = Cert("locked");
        using GpgAgentKey agentKey = Client().GetKey(_f.Key("locked").EncryptGrip);
        using PgpSecretKey external = PgpSecretKey.FromExternalKey(cert.Keys.Single(k => !k.IsPrimary), agentKey);
        try
        {
            _f.SetPinentry("cancel");
            using var input = new MemoryStream(message);
            var e = Assert.Throws<AgentRefusedException>(() => PgpMessageReader.Read(input, new MemoryStream(), new PgpReadOptions { Now = DateTimeOffset.UtcNow, ExternalKeys = [external] }));
            Assert.True(e.IsCancelled);
        }
        finally
        {
            _f.SetPinentry("onecrypto-test");
            _f.Gpgconf("--reload", "gpg-agent");
        }
    }

    // ---- CMS ----

    private static Certificate SelfSigned(string cn, ISigningKey key, SignatureSpec spec, KeyUsages usages) =>
        CertificateBuilder.CreateSelfSigned(
            new CertificateOptions
            {
                Subject = DistinguishedName.Create((KnownOids.CommonName, cn)),
                NotBefore = DateTimeOffset.UtcNow.AddDays(-1),
                NotAfter = DateTimeOffset.UtcNow.AddYears(1),
                Extensions = [Extension.Create(new BasicConstraints(false, null), critical: true), Extension.Create(new KeyUsageExtension(usages), critical: true)],
            },
            X509Signer.FromKey(key, spec));

    [Theory]
    [MemberData(nameof(Keys))]
    public void ACmsSignatureMadeThroughTheAgentVerifiesUnderOpenSsl(string name)
    {
        using GpgAgentKey agentKey = Client().GetKey(_f.Key(name).SignGrip);
        var key = (ISigningKey)agentKey;
        SignatureSpec spec = key.DefaultSpec;
        Certificate cert = SelfSigned("agent " + name, key, spec, KeyUsages.DigitalSignature);
        byte[] content = Encoding.UTF8.GetBytes("CMS content signed through gpg-agent");
        SignedData signed = SignedData.Create(content, [new CmsSignerSpec { Certificate = cert, Key = key, SignatureSpec = spec }], new SignedDataOptions { Detached = true });

        string der = Write("cms.der", signed.Encoded.ToArray()), certPem = Write("cert.pem", Encoding.ASCII.GetBytes(cert.ToPem())), data = Write("content.bin", content);
        (int code, byte[] o, string e) = Tools.Run(OpenSsl, ["cms", "-verify", "-inform", "DER", "-in", der, "-content", data, "-CAfile", certPem, "-purpose", "any", "-out", Path.Combine(_work, "out.bin")]);
        Assert.True(code == 0, e + Tools.Text(o));
        Assert.Equal(content, File.ReadAllBytes(Path.Combine(_work, "out.bin")));
    }

    [Theory]
    [InlineData("rsa")]
    [InlineData("p256")]
    public void ACmsMessageOpenSslEncryptedToTheKeyDecryptsThroughTheAgent(string name)
    {
        using GpgAgentKey agentKey = Client().GetKey(_f.Key(name).EncryptGrip);
        var key = (ISigningKey)agentKey;
        Certificate cert = SelfSigned("agent recipient " + name, key, key.DefaultSpec, name == "rsa" ? KeyUsages.KeyEncipherment | KeyUsages.DigitalSignature : KeyUsages.KeyAgreement | KeyUsages.DigitalSignature);
        byte[] content = Encoding.UTF8.GetBytes("CMS content for a key in gpg-agent");
        string certPem = Write("rcpt.pem", Encoding.ASCII.GetBytes(cert.ToPem()));
        (int code, byte[] o, string e) = Tools.Run(OpenSsl, ["cms", "-encrypt", "-aes256", "-outform", "DER", "-recip", certPem], stdin: content);
        Assert.True(code == 0, e);
        EnvelopedData env = EnvelopedData.Parse(o);
        using CmsDecryptionKey dk = CmsDecryptionKey.FromKey(agentKey, cert);
        Assert.Equal(content, env.Decrypt(dk));
    }

    // ---- two-phase signing across processes ----

    private (int Code, string Err) SignInOtherProcess(string kind, string grip, string statePath, string sigPath)
    {
        string signer = Directory.GetFiles(AppContext.BaseDirectory, "*AgentSigner.dll").Single();
        string? root = Environment.GetEnvironmentVariable("DOTNET_ROOT");
        string dotnet = root is not null && File.Exists(Path.Combine(root, "dotnet")) ? Path.Combine(root, "dotnet") : "dotnet";
        (int code, byte[] o, string e) = Tools.Run(dotnet, [signer, kind, _f.ExpectedSocket, grip, statePath, sigPath]);
        return (code, e + Tools.Text(o));
    }

    [Theory]
    [MemberData(nameof(Keys))]
    public void ACoreTwoPhaseSignatureIsPreparedHereSignedByAnotherProcessThroughTheAgentAndCompletedHere(string name)
    {
        using GpgAgentKey agentKey = Client().GetKey(_f.Key(name).SignGrip);
        var key = (ISigningKey)agentKey;
        SignatureSpec spec = key.DefaultSpec;
        byte[] data = Encoding.UTF8.GetBytes("prepared in one process, signed in a second, completed in a third step");
        var policy = RecursiveAI.OneCrypto.Policy.CryptoPolicy.Standard;
        PreparedSignature prepared = PreparedSignature.Prepare(key.PublicKey, spec, data, policy, DateTimeOffset.UtcNow);
        string state = Write("state.der", prepared.Encode()), sigPath = Path.Combine(_work, "sig.bin");
        (int code, string log) = SignInOtherProcess("core", _f.Key(name).SignGrip, state, sigPath);
        Assert.True(code == 0, log);
        byte[] signature = prepared.Complete(File.ReadAllBytes(sigPath));
        Assert.True(spec.Verify(key.PublicKey, data, signature).IsValid);

        // A state decoded from the file completes the same way: nothing but the file travelled.
        PreparedSignature again = PreparedSignature.Decode(File.ReadAllBytes(state));
        Assert.Equal(signature, again.Complete(File.ReadAllBytes(sigPath)));
    }

    [Theory]
    [MemberData(nameof(Keys))]
    public void AnOpenPgpTwoPhaseSignatureIsSignedByAnotherProcessThroughTheAgentAndGpgAcceptsIt(string name)
    {
        PgpCertificate cert = Cert(name);
        byte[] data = Encoding.UTF8.GetBytes("two-phase OpenPGP through gpg-agent\n");
        using var ms = new MemoryStream(data);
        PgpPreparedSignature prepared = PgpPreparedSignature.PrepareDetached(cert.Primary, ms, DateTimeOffset.UtcNow);
        string state = Write("pstate.der", prepared.Encode()), sigPath = Path.Combine(_work, "psig.bin");
        (int code, string log) = SignInOtherProcess("pgp", _f.Key(name).SignGrip, state, sigPath);
        Assert.True(code == 0, log);
        byte[] armored = PgpPreparedSignature.Decode(File.ReadAllBytes(state)).CompleteArmored(File.ReadAllBytes(sigPath));
        (int vc, byte[] _, string ve) = _f.GpgRun(null, "--verify", Write("p.asc", armored), Write("p.txt", data));
        Assert.True(vc == 0, ve);
    }

    [Fact]
    public void ThePreparedStateOfAKeyTheAgentDoesNotHoldIsRefusedByTheOtherProcessWithATypedError()
    {
        // A state for a key that is not in the agent: the signer process reports AgentKeyNotFoundException (exit 4) rather than anything else.
        using var rsa = RSA.Create(2048);
        PublicKeyInfo pk = PublicKeyInfo.FromAsymmetricAlgorithm(rsa);
        PreparedSignature prepared = PreparedSignature.Prepare(pk, SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256), [1], RecursiveAI.OneCrypto.Policy.CryptoPolicy.Standard, DateTimeOffset.UtcNow);
        string state = Write("foreign.der", prepared.Encode());
        (int code, string log) = SignInOtherProcess("core", new string('0', 40), state, Path.Combine(_work, "x.bin"));
        Assert.Equal(4, code);
        Assert.Contains("AgentKeyNotFoundException", log, StringComparison.Ordinal);
    }
}
