using OneCrypto.Fuzz;

namespace RecursiveAI.OneCrypto.Pdf.Tests;

/// <summary>The fuzz target's body run over byte-level mutations of its seeds with a fixed seed: a deterministic stand-in for a fuzzing run.</summary>
public class MutationSmokeTests
{
    [Fact]
    public void MutatedSignedFilesNeverThrowAndNeverLoosenOnePdf()
    {
        var seeds = PadesTarget.Seeds().ToList();
        Assert.Equal(8, seeds.Count);
        var rnd = new Random(20260101);
        for (int i = 0; i < 400; i++)
        {
            byte[] buf = (byte[])seeds[rnd.Next(seeds.Count)].Clone();
            int edits = 1 + rnd.Next(6);
            for (int e = 0; e < edits; e++)
            {
                int at = rnd.Next(buf.Length);
                switch (rnd.Next(3))
                {
                    case 0: buf[at] = (byte)rnd.Next(256); break;
                    case 1: buf[at] ^= (byte)(1 << rnd.Next(8)); break;
                    default: Array.Fill(buf, (byte)rnd.Next(256), at, Math.Min(rnd.Next(1, 40), buf.Length - at)); break;
                }
            }

            PadesTarget.Run(buf);
        }
    }
}
