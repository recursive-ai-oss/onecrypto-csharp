using OneCrypto.Fuzz;

namespace OneCrypto.Tests.Pkcs;

/// <summary>Deterministic byte-level mutation of the fuzz seeds through the container targets: nothing but the library's typed errors may escape.</summary>
public class FuzzSmokeTests
{
    private delegate void Target(ReadOnlySpan<byte> data);

    [Theory]
    [InlineData("pkcs8")]
    [InlineData("pkcs12")]
    [InlineData("ssh")]
    public void MutatedSeedsOnlyRaiseTypedErrors(string name)
    {
        (Target run, IEnumerable<byte[]> seeds) = name switch
        {
            "pkcs8" => ((Target)Pkcs8Target.Run, Pkcs8Target.Seeds()),
            "pkcs12" => (Pkcs12Target.Run, Pkcs12Target.Seeds()),
            _ => (SshTarget.Run, SshTarget.Seeds()),
        };
        byte[][] corpus = [.. seeds];
        var rnd = new Random(2024);
        for (int i = 0; i < 4000; i++)
        {
            var buf = new List<byte>(corpus[rnd.Next(corpus.Length)]);
            for (int e = 1 + rnd.Next(6); e > 0 && buf.Count > 0; e--)
            {
                int at = rnd.Next(buf.Count);
                switch (rnd.Next(4))
                {
                    case 0: buf[at] = (byte)rnd.Next(256); break;
                    case 1: buf[at] ^= (byte)(1 << rnd.Next(8)); break;
                    case 2: buf.RemoveRange(at, Math.Min(1 + rnd.Next(12), buf.Count - at)); break;
                    default: buf.Insert(at, (byte)rnd.Next(256)); break;
                }
            }

            run([.. buf]);
        }
    }
}
