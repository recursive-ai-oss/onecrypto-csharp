using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Internal;

namespace OneCrypto.Tests.Fallbacks;

/// <summary>
/// The platform availability table in <c>docs/availability.md</c> against what the dispatch code reports on this machine. The
/// document holds one section per platform; this test regenerates the section for the platform it runs on and fails when the
/// committed one differs. Set <c>ONECRYPTO_AVAILABILITY_UPDATE=1</c> to rewrite the section instead.
/// </summary>
public class AvailabilityTests(ITestOutputHelper output)
{
    internal static string Section() => Platform.AvailabilitySection();

    [Fact]
    public void TheCommittedTableMatchesThisPlatform()
    {
        string path = Path.Combine(TestFiles.Docs, "availability.md");
        string current = Section();
        string text = File.ReadAllText(path);
        string open = "<!-- platform: " + Platform.TableKey + " -->";
        int start = text.IndexOf(open, StringComparison.Ordinal);
        if (Environment.GetEnvironmentVariable("ONECRYPTO_AVAILABILITY_UPDATE") == "1")
        {
            if (start < 0)
            {
                text = text.TrimEnd() + "\n\n" + current;
            }
            else
            {
                int endMark = text.IndexOf("<!-- end -->\n", start, StringComparison.Ordinal) + "<!-- end -->\n".Length;
                text = text[..start] + current + text[endMark..];
            }

            File.WriteAllText(path, text);
            return;
        }

        if (start < 0)
        {
            output.WriteLine("No section for this platform in docs/availability.md; generated:\n" + current);
            Assert.Skip($"docs/availability.md has no section for {Platform.TableKey}");
        }

        int end = text.IndexOf("<!-- end -->\n", start, StringComparison.Ordinal) + "<!-- end -->\n".Length;
        string committed = text[start..end].ReplaceLineEndings("\n");
        // Print the whole generated section on a mismatch: the string assertion alone shows only the first difference.
        if (!string.Equals(committed, current, StringComparison.Ordinal))
        {
            Assert.Fail("The committed section differs from what this platform reports. Generated:\n" + current);
        }
    }

    [Fact]
    public void ForcingFallbacksChangesOnlyWhatHasAFallback()
    {
        var normal = Platform.Availability().ToDictionary(r => r.Algorithm);
        using IDisposable forced = Platform.ForceFallbacks();
        foreach (AvailabilityRow row in Platform.Availability())
        {
            Provider before = normal[row.Algorithm].By;
            if (before == Provider.Unsupported)
            {
                Assert.Equal(Provider.Unsupported, row.By);
            }
            else if (row.Algorithm.Contains("verify", StringComparison.Ordinal) || row.Algorithm.StartsWith("SHA", StringComparison.Ordinal) || row.Algorithm.StartsWith("ChaCha", StringComparison.Ordinal))
            {
                Assert.Equal(Provider.Fallback, row.By);
            }
        }
    }

    [Fact]
    public void TheExceptionNamesTheAlgorithmAndThePlatform()
    {
        AlgorithmNotSupportedException ex = Platform.NotSupported("ML-DSA", "the loaded OpenSSL is older than 3.5");
        Assert.Contains("ML-DSA", ex.Message, StringComparison.Ordinal);
        Assert.Contains(Platform.Rid, ex.Message, StringComparison.Ordinal);
        Assert.Contains("OpenSSL", ex.Message, StringComparison.Ordinal);
        Assert.Equal("ML-DSA", ex.Algorithm);
        Assert.IsAssignableFrom<NotSupportedException>(ex);
    }

    [Fact]
    public void RequireThrowsExactlyWhereThePlatformLacksTheAlgorithm()
    {
        if (System.Security.Cryptography.MLDsa.IsSupported)
        {
            Platform.RequireMlDsa();
        }
        else
        {
            AlgorithmNotSupportedException ex = Assert.Throws<AlgorithmNotSupportedException>(Platform.RequireMlDsa);
            Assert.Equal("ML-DSA", ex.Algorithm);
            Assert.Contains(Platform.Rid, ex.Message, StringComparison.Ordinal);
        }
    }
}
