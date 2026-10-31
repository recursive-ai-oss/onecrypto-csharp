using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Tests.Primitives;

/// <summary>
/// Argon2 and scrypt outputs produced by <c>openssl kdf</c> for parameter sets the RFC vectors do not cover: odd memory sizes,
/// many lanes, tag lengths from 4 to 1024 bytes, secret and associated data, and segments long enough to run lanes on several
/// threads. The file is written by tools/gen-kdf-vectors.sh, which records the OpenSSL version on its first line.
/// </summary>
public class KdfOracleVectorTests
{
    public static TheoryData<int> Lines()
    {
        var data = new TheoryData<int>();
        string[] lines = ReadLines();
        for (int i = 0; i < lines.Length; i++)
        {
            data.Add(i);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Lines))]
    public void OutputMatchesOpenSsl(int index)
    {
        string[] f = ReadLines()[index].Split(' ');
        if (f[0].StartsWith("argon2", StringComparison.Ordinal))
        {
            var type = f[0] switch { "argon2d" => Argon2Type.Argon2d, "argon2i" => Argon2Type.Argon2i, _ => Argon2Type.Argon2id };
            byte[] expected = Convert.FromHexString(f[8]);
            byte[] actual = Argon2.DeriveKey(
                type, Convert.FromHexString(f[1]), Convert.FromHexString(f[2]), int.Parse(f[3]), int.Parse(f[4]), int.Parse(f[5]),
                expected.Length,
                f[6] == "-" ? default : Convert.FromHexString(f[6]),
                f[7] == "-" ? default : Convert.FromHexString(f[7]));
            Assert.Equal(expected, actual);
        }
        else
        {
            byte[] expected = Convert.FromHexString(f[7]);
            byte[] actual = Scrypt.DeriveKey(
                Convert.FromHexString(f[1]), Convert.FromHexString(f[2]), int.Parse(f[3]), int.Parse(f[4]), int.Parse(f[5]), int.Parse(f[6]));
            Assert.Equal(expected, actual);
        }
    }

    // Build output lives outside the checkout, so testdata is found relative to this source file.
    private static string[] ReadLines([System.Runtime.CompilerServices.CallerFilePath] string here = "")
    {
        string root = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(here)!, "..", "..", ".."));
        return File.ReadAllLines(Path.Combine(root, "testdata", "kdf", "openssl-vectors.txt"))
            .Where(l => l.Length > 0 && l[0] != '#').ToArray();
    }
}
