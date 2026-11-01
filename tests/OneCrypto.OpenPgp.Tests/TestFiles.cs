using System.Runtime.CompilerServices;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>Finds the committed test data.</summary>
internal static class TestFiles
{
    private static string ThisFile([CallerFilePath] string path = "") => path;

    public static string TestData { get; } = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(ThisFile())!, "..", "..", "testdata"));

    public static string OpenPgp(params string[] parts) => Path.Combine([TestData, "openpgp", .. parts]);

    /// <summary>The binary form of an armored file: the armor is decoded with the library, so these tests rely on it being right.</summary>
    public static byte[] ReadArmored(string path) => Packets.Armor.Decode(File.ReadAllBytes(path)).Data;
}
