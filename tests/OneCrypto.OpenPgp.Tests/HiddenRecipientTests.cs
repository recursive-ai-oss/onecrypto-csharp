using System.Diagnostics;
using System.Text;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>RFC 9580 sections 5.1.1 and 5.1.2: session key packets that do not name their recipient.</summary>
public class HiddenRecipientTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 1, 0, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(PgpKeyProfile.Rfc4880Curve25519, 3)]
    [InlineData(PgpKeyProfile.Rfc9580, 6)]
    public void HiddenRecipientsLeaveTheRecipientOutAndTheRightKeyStillOpensTheMessage(PgpKeyProfile profile, int pkeskVersion)
    {
        PgpCertificate alice = Make(profile, "alice");
        PgpCertificate bob = Make(profile, "bob");

        byte[] named = Encrypt(alice, hidden: false);
        byte[] hidden = Encrypt(alice, hidden: true);

        PublicKeyEncryptedSessionKeyPacket n = Assert.Single(PacketParser.ParseAll(named).OfType<PublicKeyEncryptedSessionKeyPacket>());
        PublicKeyEncryptedSessionKeyPacket h = Assert.Single(PacketParser.ParseAll(hidden).OfType<PublicKeyEncryptedSessionKeyPacket>());
        Assert.Equal(pkeskVersion, h.Version);
        if (pkeskVersion == 3)
        {
            Assert.Contains(n.KeyId.ToArray(), b => b != 0);
            Assert.All(h.KeyId.ToArray(), b => Assert.Equal(0, b));
        }
        else
        {
            Assert.NotNull(n.RecipientKeyVersion);
            Assert.Null(h.RecipientKeyVersion);
            Assert.True(h.RecipientFingerprint.IsEmpty);
        }

        // The reader tries every secret key it has: the first one here is not the recipient.
        Assert.Equal("hi bcc", Decrypt(hidden, bob, alice));
        Assert.Equal("hi bcc", Decrypt(hidden, alice));
        Assert.Throws<PgpException>(() => Decrypt(hidden, bob));
    }

    // Black-box checks, run only when ONECRYPTO_GPG / ONECRYPTO_SQOP name the binaries.

    [Theory]
    [InlineData(PgpKeyProfile.Rfc4880Curve25519)]
    [InlineData(PgpKeyProfile.Rfc9580)]
    public void SqopOpensHiddenRecipientMessages(PgpKeyProfile profile)
    {
        string? sqop = Environment.GetEnvironmentVariable("ONECRYPTO_SQOP");
        Assert.SkipWhen(sqop is null, "set ONECRYPTO_SQOP to a sqop binary");
        PgpCertificate other = Make(profile, "other");
        PgpCertificate key = Make(profile, "key");
        string dir = Path.Combine(Path.GetTempPath(), "hidden-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllBytes(Path.Combine(dir, "other.key"), other.Export());
            File.WriteAllBytes(Path.Combine(dir, "key.key"), key.Export());
            (int exit, byte[] output, string err) = Run(sqop!, Encrypt(key, hidden: true), "decrypt", Path.Combine(dir, "other.key"), Path.Combine(dir, "key.key"));
            Assert.True(exit == 0, err);
            Assert.Equal("hi bcc", Encoding.UTF8.GetString(output));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void GpgOpensHiddenRecipientMessages()
    {
        string? gpg = Environment.GetEnvironmentVariable("ONECRYPTO_GPG");
        Assert.SkipWhen(gpg is null, "set ONECRYPTO_GPG to a gpg binary");
        string home = Path.Combine(Path.GetTempPath(), "hiddengpg-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(home);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(home, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        try
        {
            string[] g = ["--homedir", home, "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", ""];
            // GnuPG's own key, so the check does not depend on how a build imports foreign secret keys.
            Ok(Run(gpg!, null, [.. g, "--quick-gen-key", "gpg-owner@example.org", "ed25519", "cert,sign", "never"]));
            string fpr = Encoding.ASCII.GetString(Run(gpg!, null, [.. g, "--list-keys", "--with-colons"]).Out).Split('\n').First(l => l.StartsWith("fpr:", StringComparison.Ordinal)).Split(':')[9];
            Ok(Run(gpg!, null, [.. g, "--quick-add-key", fpr, "cv25519", "encr", "never"]));
            byte[] pub = Run(gpg!, null, [.. g, "--export", fpr]).Out;
            (int exit, byte[] output, string err) = Run(gpg!, Encrypt(PgpCertificate.Parse(pub), hidden: true, DateTimeOffset.UtcNow.AddHours(1)), [.. g, "--decrypt"]);
            Assert.True(exit == 0, err);
            Assert.Equal("hi bcc", Encoding.UTF8.GetString(output));
        }
        finally
        {
            Process.Start(new ProcessStartInfo(Path.Combine(Path.GetDirectoryName(gpg!)!, "gpgconf"), ["--homedir", home, "--kill", "all"]))?.WaitForExit();
            Directory.Delete(home, true);
        }
    }

    private static void Ok((int Exit, byte[] Out, string Err) r) => Assert.True(r.Exit == 0, r.Err);

    private static (int Exit, byte[] Out, string Err) Run(string exe, byte[]? stdin, params string[] args)
    {
        var psi = new ProcessStartInfo(exe) { RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true };
        foreach (string a in args)
        {
            psi.ArgumentList.Add(a);
        }

        using Process p = Process.Start(psi)!;
        Task<string> err = p.StandardError.ReadToEndAsync();
        var ms = new MemoryStream();
        Task copy = p.StandardOutput.BaseStream.CopyToAsync(ms);
        if (stdin is not null)
        {
            p.StandardInput.BaseStream.Write(stdin);
        }

        p.StandardInput.Close();
        p.WaitForExit();
        copy.Wait();
        return (p.ExitCode, ms.ToArray(), err.Result);
    }

    private static PgpCertificate Make(PgpKeyProfile profile, string name) =>
        PgpKeyGenerator.Generate(new PgpKeyGenerationOptions { Now = Now.AddDays(-1), UserIds = [name], Profile = profile });

    private static byte[] Encrypt(PgpCertificate recipient, bool hidden, DateTimeOffset? at = null)
    {
        using var enc = new MemoryStream();
        PgpMessageWriter.Write(new MemoryStream("hi bcc"u8.ToArray()), enc, new PgpWriteOptions { Now = at ?? Now, Recipients = [PgpCertificate.Parse(recipient.ExportPublic())], HiddenRecipients = hidden });
        return enc.ToArray();
    }

    private static string Decrypt(byte[] message, params PgpCertificate[] secretKeys)
    {
        using var dec = new MemoryStream();
        PgpMessageReader.Read(new MemoryStream(message), dec, new PgpReadOptions { Now = Now, SecretKeys = secretKeys });
        return Encoding.UTF8.GetString(dec.ToArray());
    }
}
