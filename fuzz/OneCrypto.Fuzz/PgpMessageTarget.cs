using System.Runtime.CompilerServices;
using System.Text;
using RecursiveAI.OneCrypto.OpenPgp;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Fuzz;

/// <summary>
/// OpenPGP messages. The first byte picks the surface: decrypt and verify a message (with a fixed test key and password), verify a detached
/// signature, verify a cleartext-signed message, or read an inline-signed message in either form. Only <see cref="PgpException"/> and
/// <see cref="OpenPgpParseException"/> may come out. KDF costs are capped small so a hostile S2K cannot allocate gigabytes.
/// </summary>
internal static class PgpMessageTarget
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly OpenPgpLimits Small = new() { MaxPacketBodyLength = 1 << 20, MaxPackets = 4096, MaxSubpackets = 256, MaxArmorLineLength = 2048, MaxArmoredBytes = 1 << 22 };
    private static readonly CryptoPolicy Policy = CryptoPolicy.Standard with { KdfLimits = new KdfLimits { MaxMemoryBytes = 1 << 22, MaxArgon2Passes = 4, MaxArgon2Parallelism = 4 } };

    private static string ThisFile([CallerFilePath] string path = "") => path;

    private static string Data(string name) => Path.Combine(Path.GetDirectoryName(ThisFile())!, "..", "..", "testdata", "openpgp", "rfc9580", name);

    private static readonly Lazy<(PgpCertificate Secret, PgpCertificate Cert)> Keys = new(() =>
    {
        var secret = PgpCertificate.Parse(File.ReadAllBytes(Data("A_4.asc")));
        return (secret, PgpCertificate.Parse(File.ReadAllBytes(Data("A_3.asc"))));
    });

    private static PgpReadOptions Options() => new()
    {
        Now = Now,
        Certificates = [Keys.Value.Cert],
        SecretKeys = [Keys.Value.Secret],
        MessagePasswords = ["password"u8.ToArray()],
        Policy = Policy,
        Limits = Small,
    };

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 1)
        {
            return;
        }

        byte[] rest = data[1..].ToArray();
        try
        {
            switch (data[0] % 4)
            {
                case 0:
                    PgpMessageReader.Read(new MemoryStream(rest), Stream.Null, Options());
                    break;
                case 1:
                    PgpMessageReader.VerifyDetached(new MemoryStream("fuzz"u8.ToArray()), new MemoryStream(rest), Options());
                    break;
                case 2:
                    PgpMessageReader.VerifyCleartext(new MemoryStream(rest), Stream.Null, Options());
                    break;
                default:
                    PgpMessageReader.ReadSigned(new MemoryStream(rest), Stream.Null, Options());
                    break;
            }
        }
        catch (PgpException)
        {
        }
        catch (OpenPgpParseException)
        {
        }
    }

    public static IEnumerable<byte[]> Seeds()
    {
        yield return [0, 0xC0 | 11, 3, (byte)'b', 0, 0];
        if (!Directory.Exists(Path.GetDirectoryName(Data("x"))))
        {
            yield break;
        }

        // The Argon2 samples would ask for gigabytes; the limits above refuse them, so they stay out of the corpus.
        foreach (string name in new[] { "A_7.asc", "A_8_5.asc", "A_9_5.asc", "A_10_5.asc", "A_11_5.asc" })
        {
            byte[] armored = File.ReadAllBytes(Data(name));
            yield return [0, .. armored];
            yield return [3, .. armored];
            if (Armor.TryDecode(armored, out ArmorBlock? block, out _) && block is not null)
            {
                yield return [0, .. block.Data];
            }
        }

        yield return [2, .. File.ReadAllBytes(Data("A_6_cleartext.asc"))];
        yield return [3, .. File.ReadAllBytes(Data("A_6_cleartext.asc"))];
        yield return [1, .. File.ReadAllBytes(Data("A_2.asc"))];
        yield return [1, .. File.ReadAllBytes(Data("A_6.asc"))];
        // A SEIPD v1 message and a short v2 message written by the library itself.
        PgpCertificate cert = Keys.Value.Cert;
        foreach (bool v1 in new[] { true, false })
        {
            using var enc = new MemoryStream();
            PgpMessageWriter.Write(new MemoryStream(Encoding.ASCII.GetBytes("fuzz seed message")), enc, new PgpWriteOptions { Now = Now, Recipients = [cert], ForceSeipd1 = v1 });
            yield return [0, .. enc.ToArray()];
        }

        // LibrePGP OCB Encrypted Data, and bzip2-compressed messages (one hand-made, one from GnuPG).
        using (var ocb = new MemoryStream())
        {
            PgpMessageWriter.Write(new MemoryStream(Encoding.ASCII.GetBytes("fuzz seed message")), ocb, new PgpWriteOptions { Now = Now, Recipients = [cert], ForceLibrePgp = true });
            yield return [0, .. ocb.ToArray()];
        }

        foreach (string name in new[] { "msg-bzip2-literal.pgp", "msg-bzip2.gpg", "msg-v5-ocbed.gpg", "msg-pw-ocbed.gpg" })
        {
            yield return [0, .. File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(Data("x"))!, "..", "librepgp", name))];
        }
    }
}
