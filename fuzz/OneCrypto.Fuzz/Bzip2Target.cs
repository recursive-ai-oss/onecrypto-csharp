using System.Runtime.CompilerServices;
using RecursiveAI.OneCrypto.OpenPgp;

namespace OneCrypto.Fuzz;

/// <summary>The bzip2 decompressor: only <see cref="InvalidDataException"/> may come out, and the output read is capped.</summary>
internal static class Bzip2Target
{
    private static string ThisFile([CallerFilePath] string path = "") => path;

    public static void Run(ReadOnlySpan<byte> data)
    {
        using var s = new Bzip2DecompressStream(new MemoryStream(data.ToArray()));
        byte[] buf = new byte[64 * 1024];
        long total = 0;
        try
        {
            int n;
            while ((n = s.Read(buf, 0, buf.Length)) > 0 && (total += n) < (64L << 20))
            {
            }
        }
        catch (InvalidDataException)
        {
        }
    }

    public static IEnumerable<byte[]> Seeds()
    {
        string dir = Path.Combine(Path.GetDirectoryName(ThisFile())!, "..", "..", "testdata", "openpgp", "librepgp");
        yield return File.ReadAllBytes(Path.Combine(dir, "bzip2-sample.bz2"));
        yield return "BZh9"u8.ToArray();
        yield return [.. "BZh1"u8, 0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 0, 0, 0, 0];
    }
}
