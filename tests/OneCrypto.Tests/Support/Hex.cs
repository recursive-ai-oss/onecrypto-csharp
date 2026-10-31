namespace OneCrypto.Tests.Support;

internal static class Hex
{
    /// <summary>Decodes hex text; the dash used in vector files for "empty" is the empty array. Whitespace is ignored.</summary>
    public static byte[] Decode(string text)
    {
        if (text == "-")
        {
            return [];
        }

        return Convert.FromHexString(string.Concat(text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)));
    }

    public static string Encode(ReadOnlySpan<byte> data) => Convert.ToHexString(data);
}
