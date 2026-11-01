using System.Text;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Fuzz;

/// <summary>Argon2 PHC strings: whatever parses must format back to the same text, and nothing but the typed error may escape.</summary>
internal static class PhcTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        string s = Encoding.Latin1.GetString(data);
        if (Argon2Phc.TryParse(s, out Argon2PhcHash? h) && h is not null)
        {
            string again = Argon2Phc.Format(h);
            if (!string.Equals(again, s, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("A PHC string parsed but did not format back to itself.");
            }
        }

        try
        {
            _ = Argon2Phc.Parse(s);
        }
        catch (Argon2PhcFormatException)
        {
        }
    }

    public static IEnumerable<byte[]> Seeds()
    {
        yield return Encoding.ASCII.GetBytes("$argon2id$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk");
        yield return Encoding.ASCII.GetBytes("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHRzYWx0$RdescudvJCsgt3ub+b+dWRWJTmaaJObG");
        yield return Encoding.ASCII.GetBytes("$argon2d$v=19$m=8,t=1,p=1$AAAAAAAAAAA$AAAAAA");
    }
}
