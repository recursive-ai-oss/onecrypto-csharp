using System.Text;
using RecursiveAI.OneCrypto.OpenPgp;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Fuzz;

/// <summary>
/// OpenPGP key handling. The first byte picks the surface: unlock the secret keys of a certificate (S2K parameters and protected key material come from
/// the input; Argon2 costs are capped small), evaluate a certificate and edit it with a throwaway key (merge with itself, re-protect), or decode a
/// serialised two-phase signature and try to complete it with junk. Only <see cref="PgpException"/> and <see cref="OpenPgpParseException"/> may come out.
/// </summary>
internal static class PgpKeyTarget
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly OpenPgpLimits Small = new() { MaxPacketBodyLength = 1 << 20, MaxPackets = 4096, MaxSubpackets = 256, MaxArmorLineLength = 2048, MaxArmoredBytes = 1 << 22 };
    private static readonly KdfLimits Cheap = new() { MaxMemoryBytes = 1 << 22, MaxArgon2Passes = 4, MaxArgon2Parallelism = 4 };
    private static readonly byte[] Password = "fuzz"u8.ToArray();

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 1)
        {
            return;
        }

        byte[] rest = data[1..].ToArray();
        try
        {
            switch (data[0] % 3)
            {
                case 0:
                    Unlock(rest);
                    break;
                case 1:
                    Edit(rest);
                    break;
                default:
                    State(rest);
                    break;
            }
        }
        catch (OpenPgpParseException)
        {
        }
        catch (PgpException)
        {
        }
    }

    private static void Unlock(byte[] input)
    {
        foreach (byte[] block in new[] { input })
        {
            foreach (PgpCertificate c in PgpCertificate.ParseAll(block))
            {
                foreach (PgpKey k in c.Keys)
                {
                    if (PgpSecretKey.TryUnlock(k, [Password, []], out PgpSecretKey? u, Cheap))
                    {
                        // An unlocked key that parses must be able to try signing; a malformed secret may only fail with a typed error.
                        try
                        {
                            _ = u!.SigningKey;
                        }
                        catch (PgpException)
                        {
                        }
                        finally
                        {
                            u!.Dispose();
                        }
                    }
                }
            }
        }
    }

    private static void Edit(byte[] input)
    {
        foreach (PgpCertificate c in PgpCertificate.ParseAll(input))
        {
            _ = c.Primary.StateAt(Now);
            foreach (PgpKey k in c.Keys)
            {
                _ = k.StateAt(Now);
            }

            PgpCertificate merged = PgpKeyEditor.Merge(c, c);
            if (merged.Transferable.Packets.Count != c.Transferable.Packets.Count)
            {
                throw new InvalidOperationException("merging a certificate with itself changed it");
            }

            _ = c.ToPublicCertificate().Export(armor: true);
            _ = PgpUserIds.IsCertified(c, "a", [c], Now);
        }
    }

    private static void State(byte[] input)
    {
        if (PgpPreparedSignature.TryDecode(input, out PgpPreparedSignature? p, out _))
        {
            if (!PgpPreparedSignature.Decode(input).Encode().AsSpan().SequenceEqual(p!.Encode()))
            {
                throw new InvalidOperationException("decoding the same state twice gave different states");
            }

            _ = p.ToSign.Length;
            try
            {
                _ = p.Complete(new byte[64]);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
            }
        }
    }

    public static IEnumerable<byte[]> Seeds()
    {
        foreach (PgpKeyProfile profile in new[] { PgpKeyProfile.Rfc9580, PgpKeyProfile.Rfc4880Curve25519, PgpKeyProfile.NistP256 })
        {
            PgpCertificate protectedKey = PgpKeyGenerator.Generate(new PgpKeyGenerationOptions { Now = Now, Profile = profile, UserIds = ["Fuzz"], Password = Password, Policy = CryptoPolicy.Standard with { KdfLimits = Cheap } });
            yield return [0, .. protectedKey.Export()];
            yield return [1, .. protectedKey.ToPublicCertificate().Export()];
            PgpPreparedSignature p = PgpPreparedSignature.PrepareDetached(protectedKey.Primary, new MemoryStream(Encoding.ASCII.GetBytes("fuzz")), Now);
            yield return [2, .. p.Encode()];
        }
    }
}
