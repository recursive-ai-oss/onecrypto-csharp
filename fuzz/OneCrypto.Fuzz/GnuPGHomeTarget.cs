using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.OpenPgp.GnuPG;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Fuzz;

/// <summary>
/// GnuPG home files. The first byte picks the surface: a keybox (an accepted one must write back byte for byte, and every OpenPGP blob
/// is read as a key), a private-key file (parsed, then unlocked with a fixed passphrase and a small S2K budget, and its key objects built),
/// the binary trust database, the owner-trust export text, or a legacy keyring. Only the library's typed exceptions may come out; a
/// keybox rewrite that differs from the input is reported as an <see cref="InvalidOperationException"/>.
/// </summary>
internal static class GnuPGHomeTarget
{
    private static readonly GnuPGLimits Small = new() { MaxBlobLength = 1 << 20, MaxBlobs = 4096, MaxKeyFileLength = 1 << 16, MaxS2kCount = 1 << 16, MaxTrustRecords = 4096, MaxTextLines = 4096 };

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 1)
        {
            return;
        }

        byte[] rest = data[1..].ToArray();
        try
        {
            switch (data[0] % 5)
            {
                case 0:
                    Keybox(rest);
                    break;
                case 1:
                    KeyFile(rest);
                    break;
                case 2:
                    Trust(rest);
                    break;
                case 3:
                    OwnerTrust(rest);
                    break;
                default:
                    Ring(rest);
                    break;
            }
        }
        catch (GnuPGFormatException)
        {
        }
        catch (OpenPgpParseException)
        {
        }
        catch (GnuPGWrongPassphraseException)
        {
        }
        catch (KdfLimitExceededException)
        {
        }
        catch (NotSupportedException)
        {
        }
    }

    private static void Keybox(byte[] input)
    {
        if (!RecursiveAI.OneCrypto.OpenPgp.GnuPG.Keybox.TryParse(input, out Keybox? box, out _, Small))
        {
            // Parse must agree with TryParse.
            try
            {
                _ = RecursiveAI.OneCrypto.OpenPgp.GnuPG.Keybox.Parse(input, Small);
            }
            catch (GnuPGFormatException)
            {
                return;
            }

            throw new InvalidOperationException("TryParse refused what Parse accepted");
        }

        using var ms = new MemoryStream();
        box!.Write(ms);
        if (!ms.ToArray().AsSpan().SequenceEqual(input))
        {
            throw new InvalidOperationException("keybox rewrite differs from the input");
        }

        foreach (KeyboxOpenPgpBlob b in box.OpenPgpBlobs)
        {
            try
            {
                _ = b.ReadKey().Primary.FingerprintHex;
            }
            catch (OpenPgpParseException)
            {
            }
        }
    }

    private static void KeyFile(byte[] input)
    {
        if (!GnuPGKeyFile.TryParse(input, out GnuPGKeyFile? file, out _, Small))
        {
            return;
        }

        _ = file!.Algorithm;
        _ = file.Curve;
        _ = file.Created;
        _ = file.ProtectedAt;
        _ = file.Description;
        _ = file.Comment;
        _ = file.Token;
        using GnuPGSecretKey key = file.Unlock("onecrypto-test", Small);
        if (file.Algorithm == "rsa" || file.Curve is not null)
        {
            try
            {
                using var s = key.ToSigningKey();
            }
            catch (CryptographicException)
            {
                // The platform refused an inconsistent key; a typed error is the expected outcome.
            }
        }
    }

    private static void Trust(byte[] input)
    {
        if (TrustDb.TryParse(input, out TrustDb? db, out _, Small))
        {
            _ = db!.OwnerTrust.Count;
        }
    }

    private static void OwnerTrust(byte[] input)
    {
        string text = System.Text.Encoding.Latin1.GetString(input);
        IReadOnlyList<OwnerTrustEntry> entries = OwnerTrustExport.Parse(text, Small);
        _ = OwnerTrustExport.Format(entries);
    }

    private static void Ring(byte[] input) =>
        LegacyKeyring.TryRead(input, out _, out _, new OpenPgpLimits { MaxPacketBodyLength = 1 << 20, MaxPackets = 4096, MaxSubpackets = 256 });

    private static string ThisFile([CallerFilePath] string path = "") => path;

    public static IEnumerable<byte[]> Seeds()
    {
        string root = Path.Combine(Path.GetDirectoryName(ThisFile())!, "..", "..", "testdata", "gnupg", "2.4.8");
        foreach (string home in new[] { "main", "special" })
        {
            Add(root, home, "pubring.kbx", 0, out byte[]? kbx);
            if (kbx is not null)
            {
                yield return kbx;
            }

            string keys = Path.Combine(root, home, "private-keys-v1.d");
            if (Directory.Exists(keys))
            {
                string[] files = Directory.GetFiles(keys, "*.key");
                Array.Sort(files, StringComparer.Ordinal);
                for (int i = 0; i < files.Length && i < 6; i++)
                {
                    yield return [1, .. File.ReadAllBytes(files[i])];
                }
            }

            Add(root, home, "trustdb.gpg", 2, out byte[]? tdb);
            if (tdb is not null)
            {
                yield return tdb;
            }

            Add(root, home, "ownertrust.txt", 3, out byte[]? ot);
            if (ot is not null)
            {
                yield return ot;
            }
        }

        Add(root, "legacy", "pubring.gpg", 4, out byte[]? ring);
        if (ring is not null)
        {
            yield return ring;
        }
    }

    private static void Add(string root, string home, string name, byte surface, out byte[]? seed)
    {
        string path = Path.Combine(root, home, name);
        seed = File.Exists(path) ? [surface, .. File.ReadAllBytes(path)] : null;
    }
}
