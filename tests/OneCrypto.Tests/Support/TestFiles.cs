using System.Runtime.CompilerServices;

namespace OneCrypto.Tests.Support;

/// <summary>Finds the committed test data and the fetched vector suites.</summary>
internal static class TestFiles
{
    private static readonly string Here = Path.GetDirectoryName(ThisFile())!;

    private static string ThisFile([CallerFilePath] string path = "") => path;

    /// <summary>The repository's <c>testdata</c> folder.</summary>
    public static string TestData => Path.GetFullPath(Path.Combine(Here, "..", "..", "..", "testdata"));

    /// <summary>The repository's <c>tools</c> folder.</summary>
    public static string Tools => Path.GetFullPath(Path.Combine(Here, "..", "..", "..", "tools"));

    /// <summary>
    /// The folder the vector suites are fetched into (<c>tools/fetch-*.sh</c>): <c>ONECRYPTO_VECTORS</c>, or <c>~/onecrypto/vectors</c>.
    /// </summary>
    public static string Vectors =>
        Environment.GetEnvironmentVariable("ONECRYPTO_VECTORS")
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "onecrypto", "vectors");

    /// <summary>The path of a Wycheproof <c>testvectors_v1</c> file, or skips the calling test when the suite has not been fetched.</summary>
    public static string Wycheproof(string file)
    {
        string path = Path.Combine(Vectors, "wycheproof", "testvectors_v1", file);
        if (!File.Exists(path))
        {
            Assert.Skip($"Wycheproof vectors are not fetched ({path}); run tools/fetch-wycheproof.sh");
        }

        return path;
    }

    /// <summary>The repository's <c>docs</c> folder.</summary>
    public static string Docs => Path.GetFullPath(Path.Combine(Here, "..", "..", "..", "docs"));

    /// <summary>The path of a NIST CAVP SHA-3/SHAKE response file, or skips the calling test when the vectors have not been fetched.</summary>
    public static string Cavp(string file)
    {
        string path = Path.Combine(Vectors, "cavp-sha3", file);
        if (!File.Exists(path))
        {
            Assert.Skip($"CAVP SHA-3 vectors are not fetched ({path}); run tools/fetch-cavp-sha3.sh");
        }

        return path;
    }
}
