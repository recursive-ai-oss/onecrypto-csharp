using System.Linq;
using System.Text;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Pkcs;

namespace OneCrypto.Fuzz;

/// <summary>
/// <c>Crypto.Load</c> end to end: the sniffing table and every parser behind it, with a password callback that always answers. Costs
/// read from the input are capped low so a hostile iteration count cannot stall the run; the limit checks themselves are what is
/// exercised. Only <see cref="CryptoLoadException"/> may come out; a load that succeeds is disposed.
/// </summary>
internal static class LoadTarget
{
    private static readonly PkcsLimits Tight = new() { MaxIterations = 300, MaxBags = 64, Kdf = new KdfLimits { MaxScryptWork = 1 << 12, MaxMemoryBytes = 1 << 22, MaxBcryptRounds = 2 } };

    public static void Run(ReadOnlySpan<byte> data)
    {
        try
        {
            using LoadedItems items = CryptoLoader.Run(data, static _ => "fuzz", Tight);
            if (items.Count < 0)
            {
                throw new InvalidOperationException("negative count");
            }
        }
        catch (CryptoLoadException)
        {
        }
    }

    public static IEnumerable<byte[]> Seeds()
    {
        // Every other parser target's starting files, without their selector byte, plus the PEM and text forms.
        foreach (byte[] s in X509Target.Seeds().Concat(OcspTarget.Seeds()).Concat(Pkcs8Target.Seeds()).Concat(SshTarget.Seeds()))
        {
            if (s.Length > 1)
            {
                yield return s[1..];
                if (s[1] == 0x30)
                {
                    yield return Encoding.ASCII.GetBytes(RecursiveAI.OneCrypto.Pem.PemCodec.Write("CERTIFICATE", s.AsSpan(1)));
                    yield return Encoding.ASCII.GetBytes(RecursiveAI.OneCrypto.Pem.PemCodec.Write("X509 CRL", s.AsSpan(1)));
                    yield return Encoding.ASCII.GetBytes(RecursiveAI.OneCrypto.Pem.PemCodec.Write("ENCRYPTED PRIVATE KEY", s.AsSpan(1)));
                }
            }
        }

        foreach (byte[] s in Pkcs12Target.Seeds())
        {
            yield return s;
        }
    }
}
