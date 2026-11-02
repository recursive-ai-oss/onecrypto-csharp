using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Keys.Agents;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.Wire.Ssh;

namespace OneCrypto.Keys.Tests;

/// <summary>An OpenSSH ssh-agent in a scratch directory with generated test keys. The binaries come from <c>ONECRYPTO_SSH_BIN</c> (default <c>/usr/bin</c>).</summary>
public sealed class SshAgentFixture : IDisposable
{
    private readonly string? _skip;
    private readonly Process? _agent;

    public SshAgentFixture()
    {
        string bin = Environment.GetEnvironmentVariable("ONECRYPTO_SSH_BIN") ?? "/usr/bin";
        if (!File.Exists(Path.Combine(bin, "ssh-agent")) || !File.Exists(Path.Combine(bin, "ssh-keygen")) || !File.Exists(Path.Combine(bin, "ssh-add")))
        {
            _skip = "no OpenSSH binaries (set ONECRYPTO_SSH_BIN)";
            Dir = Socket = Bin = string.Empty;
            return;
        }

        Bin = bin;
        Dir = Tools.ShortTemp("ssh");
        Socket = Path.Combine(Dir, "agent.sock");
        // A confirmation helper that always says no, for keys added with ssh-add -c.
        string askpass = Path.Combine(Dir, "deny.sh");
        File.WriteAllText(askpass, "#!/bin/sh\nexit 1\n");
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(askpass, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        var psi = new ProcessStartInfo(Path.Combine(bin, "ssh-agent")) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        psi.ArgumentList.Add("-D");
        psi.ArgumentList.Add("-a");
        psi.ArgumentList.Add(Socket);
        psi.Environment["SSH_ASKPASS"] = askpass;
        psi.Environment["SSH_ASKPASS_REQUIRE"] = "force";
        psi.Environment.Remove("SSH_AUTH_SOCK");
        _agent = Process.Start(psi)!;
        for (int i = 0; i < 100 && !File.Exists(Socket); i++)
        {
            Thread.Sleep(50);
        }

        foreach ((string name, string type, string bits) in new[] { ("rsa", "rsa", "3072"), ("p256", "ecdsa", "256"), ("p384", "ecdsa", "384"), ("p521", "ecdsa", "521"), ("ed25519", "ed25519", "") })
        {
            Generate(name, type, bits, confirm: false);
        }

        Generate("confirm", "ed25519", string.Empty, confirm: true);
    }

    public string Bin { get; }

    public string Dir { get; }

    public string Socket { get; }

    public void RequireSsh() => Assert.SkipWhen(_skip is not null, _skip ?? string.Empty);

    public string PublicFile(string name) => Path.Combine(Dir, "key_" + name + ".pub");

    public SshPublicKey PublicKey(string name) => SshPublicKey.ParseAuthorizedKey(File.ReadAllText(PublicFile(name)));

    private void Generate(string name, string type, string bits, bool confirm)
    {
        string file = Path.Combine(Dir, "key_" + name);
        List<string> args = ["-q", "-t", type, "-N", string.Empty, "-C", "test-" + name, "-f", file];
        if (bits.Length > 0)
        {
            args.AddRange(["-b", bits]);
        }

        Assert.Equal(0, Tools.Run(Path.Combine(Bin, "ssh-keygen"), args).Code);
        Dictionary<string, string?> env = new() { ["SSH_AUTH_SOCK"] = Socket, ["SSH_ASKPASS"] = null, ["SSH_ASKPASS_REQUIRE"] = null };
        List<string> add = confirm ? ["-c", file] : [file];
        (int code, byte[] o, string e) = Tools.Run(Path.Combine(Bin, "ssh-add"), add, env);
        Assert.True(code == 0, Tools.Text(o) + e);
    }

    public (int Code, byte[] Out, string Err) Keygen(byte[]? stdin, params string[] args) => Tools.Run(Path.Combine(Bin, "ssh-keygen"), args, stdin: stdin);

    public void Dispose()
    {
        if (_agent is not null)
        {
            try
            {
                _agent.Kill(entireProcessTree: true);
                _agent.WaitForExit(5000);
            }
            catch (InvalidOperationException)
            {
                // already gone
            }

            _agent.Dispose();
            try
            {
                Directory.Delete(Dir, recursive: true);
            }
            catch (IOException)
            {
                // best effort
            }
        }
    }
}

/// <summary>The ssh-agent backend against OpenSSH's ssh-agent: listing, signing with every key type, SSHSIG files that <c>ssh-keygen -Y verify</c> accepts, and the failure modes.</summary>
public class SshAgentTests : IClassFixture<SshAgentFixture>
{
    private readonly SshAgentFixture _f;

    public SshAgentTests(SshAgentFixture fixture)
    {
        _f = fixture;
        fixture.RequireSsh();
    }

    private SshAgentClient Client() => new(new SshAgentOptions { SocketPath = _f.Socket });

    public static TheoryData<string> Names => ["rsa", "p256", "p384", "p521", "ed25519"];

    [Fact]
    public void TheAgentsKeysAreListedWithTheirComments()
    {
        IReadOnlyList<SshAgentIdentity> ids = Client().ListIdentities();
        Assert.Equal(6, ids.Count);
        foreach (string n in new[] { "rsa", "p256", "p384", "p521", "ed25519", "confirm" })
        {
            SshAgentIdentity id = ids.Single(i => i.Comment == "test-" + n);
            Assert.Equal(_f.PublicKey(n), id.PublicKey);
        }
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void AKeySignsAndTheSignatureVerifiesIndependently(string name)
    {
        using SshAgentKey key = Client().GetKey(_f.PublicKey(name));
        byte[] data = Encoding.UTF8.GetBytes("signed through ssh-agent");
        switch (name)
        {
            case "rsa":
                foreach (string h in new[] { "SHA256", "SHA512" })
                {
                    var hash = new HashAlgorithmName(h);
                    byte[] sig = key.Sign(data, SignatureSpec.RsaPkcs1(hash));
                    using RSA rsa = key.PublicKey.ToRsa();
                    Assert.True(rsa.VerifyData(data, sig, hash, RSASignaturePadding.Pkcs1), h);
                }

                // The SHA-1 ssh-rsa scheme, PSS and a digest are all refused before anything is sent.
                Assert.False(key.Supports(SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA1)));
                Assert.False(key.Supports(SignatureSpec.RsaPss(HashAlgorithmName.SHA256)));
                Assert.Throws<NotSupportedException>(() => key.Sign(data, SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA1)));
                break;
            case "ed25519":
                byte[] es = key.Sign(data, SignatureSpec.Ed25519());
                Assert.True(Ed25519.Verify(key.PublicKey.KeyBits.Span, data, es));
                break;
            default:
                HashAlgorithmName eh = name == "p256" ? HashAlgorithmName.SHA256 : name == "p384" ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA512;
                foreach (EcdsaSignatureFormat f in new[] { EcdsaSignatureFormat.Der, EcdsaSignatureFormat.Rfc4754 })
                {
                    byte[] sig = key.Sign(data, SignatureSpec.Ecdsa(eh, f));
                    using ECDsa ec = key.PublicKey.ToECDsa();
                    Assert.True(ec.VerifyData(data, sig, eh, f == EcdsaSignatureFormat.Der ? DSASignatureFormat.Rfc3279DerSequence : DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
                }

                Assert.False(key.Supports(SignatureSpec.Ecdsa(eh == HashAlgorithmName.SHA256 ? HashAlgorithmName.SHA512 : HashAlgorithmName.SHA256)));
                break;
        }

        Assert.Throws<NotSupportedException>(() => key.SignDigest(new byte[32], key.DefaultSpec));
    }

    private static byte[] SshString(byte[] b) => [.. new byte[] { (byte)(b.Length >> 24), (byte)(b.Length >> 16), (byte)(b.Length >> 8), (byte)b.Length }, .. b];

    private static byte[] SshString(string s) => SshString(Encoding.ASCII.GetBytes(s));

    /// <summary>An SSHSIG file (OpenSSH PROTOCOL.sshsig) over <paramref name="message"/>, with the signature made by the agent.</summary>
    private static string SshSig(SshAgentKey key, byte[] message, string ns, HashAlgorithmName spec)
    {
        // The agent signs: "SSHSIG" || string namespace || string reserved || string hash_algorithm || string H(message).
        string hashName = spec == HashAlgorithmName.SHA256 ? "sha256" : "sha512";
        byte[] signed = [.. "SSHSIG"u8.ToArray(), .. SshString(ns), .. SshString(string.Empty), .. SshString(hashName), .. SshString(CryptographicOperations.HashData(spec, message))];
        SignatureSpec s = key.SshKey.Type == SshKeyType.Rsa ? SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA512) : key.DefaultSpec;
        byte[] blob = key.SignToSshSignature(signed, s);
        byte[] file = [.. "SSHSIG"u8.ToArray(), 0, 0, 0, 1, .. SshString(key.SshKey.Blob.ToArray()), .. SshString(ns), .. SshString(string.Empty), .. SshString(hashName), .. SshString(blob)];
        string b64 = Convert.ToBase64String(file, Base64FormattingOptions.None);
        var sb = new StringBuilder("-----BEGIN SSH SIGNATURE-----\n");
        for (int i = 0; i < b64.Length; i += 70)
        {
            sb.Append(b64, i, Math.Min(70, b64.Length - i)).Append('\n');
        }

        return sb.Append("-----END SSH SIGNATURE-----\n").ToString();
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void AnSshsigMadeThroughTheAgentVerifiesUnderSshKeygen(string name)
    {
        SshPublicKey pub = _f.PublicKey(name);
        using SshAgentKey key = Client().GetKey(pub);
        byte[] message = Encoding.UTF8.GetBytes("a file signed with an ssh-agent key\n");
        string sig = SshSig(key, message, "file", HashAlgorithmName.SHA512);
        string sigFile = Path.Combine(_f.Dir, "msg-" + name + ".sig"), allowed = Path.Combine(_f.Dir, "allowed-" + name);
        File.WriteAllText(sigFile, sig);
        File.WriteAllText(allowed, "signer@example.org " + pub.ToAuthorizedKey() + "\n");
        (int code, byte[] o, string e) = _f.Keygen(message, "-Y", "verify", "-f", allowed, "-I", "signer@example.org", "-n", "file", "-s", sigFile);
        Assert.True(code == 0, Tools.Text(o) + e);
        Assert.Contains("Good \"file\" signature", Tools.Text(o), StringComparison.Ordinal);

        // A different message must not verify under the same signature.
        (int bad, byte[] _, string _) = _f.Keygen(Encoding.UTF8.GetBytes("another message\n"), "-Y", "verify", "-f", allowed, "-I", "signer@example.org", "-n", "file", "-s", sigFile);
        Assert.NotEqual(0, bad);
    }

    [Fact]
    public void AnX509PublicKeyFindsTheAgentsKey()
    {
        SshPublicKey pub = _f.PublicKey("p256");
        using SshAgentKey? found = Client().FindKey(pub.ToPublicKeyInfo());
        Assert.NotNull(found);
        Assert.Equal("test-p256", found.Comment);
    }

    [Fact]
    public void AKeyTheAgentDoesNotHoldIsATypedNotFound()
    {
        byte[] pub = RandomNumberGenerator.GetBytes(32);
        byte[] blob = [.. SshString("ssh-ed25519"), .. SshString(pub)];
        Assert.Throws<AgentKeyNotFoundException>(() => Client().GetKey(SshPublicKey.Parse(blob)));
    }

    [Fact]
    public void AKeyHeldUnderConfirmationThatTheUserDeniesIsATypedRefusal()
    {
        using SshAgentKey key = Client().GetKey(_f.PublicKey("confirm"));
        Assert.Throws<AgentRefusedException>(() => key.Sign([1, 2, 3], SignatureSpec.Ed25519()));
    }

    [Fact]
    public void NoAgentIsATypedUnavailableError()
    {
        string sock = Path.Combine(_f.Dir, "nothing.sock");
        var e = Assert.Throws<AgentUnavailableException>(() => new SshAgentClient(new SshAgentOptions { SocketPath = sock }).ListIdentities());
        Assert.Equal(sock, e.SocketPath);

        string? saved = Environment.GetEnvironmentVariable("SSH_AUTH_SOCK");
        try
        {
            Environment.SetEnvironmentVariable("SSH_AUTH_SOCK", null);
            Assert.Throws<AgentUnavailableException>(() => new SshAgentClient().ListIdentities());
        }
        finally
        {
            Environment.SetEnvironmentVariable("SSH_AUTH_SOCK", saved);
        }
    }

    [Fact]
    public void TheDefaultSocketComesFromSshAuthSock()
    {
        string? saved = Environment.GetEnvironmentVariable("SSH_AUTH_SOCK");
        try
        {
            Environment.SetEnvironmentVariable("SSH_AUTH_SOCK", _f.Socket);
            Assert.Equal(6, new SshAgentClient().ListIdentities().Count);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SSH_AUTH_SOCK", saved);
        }
    }

    [Fact]
    public void DataThatDoesNotFitOneAgentMessageIsALimitError()
    {
        using SshAgentKey key = Client().GetKey(_f.PublicKey("ed25519"));
        Assert.Throws<AgentLimitException>(() => key.Sign(new byte[300 * 1024], SignatureSpec.Ed25519()));
    }
}
