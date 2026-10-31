using System.Security.Cryptography;

namespace OneCrypto.Timing;

/// <summary>
/// The registry of timing targets. A primitive adds its own file with a static method returning its targets and one line
/// in <see cref="All"/>. The list is explicit: nothing is discovered by reflection.
/// </summary>
internal static class Targets
{
    public static IReadOnlyList<TimingTarget> All { get; } =
    [
        .. SelfCheck.Targets(),
        .. CurveTargets.Targets(),
        .. AesModesTargets.Targets(),
        .. LegacyCipherTargets.Targets(),
        .. KdfTargets.Targets(),
        .. FallbackTargets.Targets(),
    ];
}

/// <summary>
/// Targets whose answer is known, used to prove the harness can see a leak and does not invent one.
/// </summary>
internal static class SelfCheck
{
    private const int Length = 1024;

    // Written so the compare cannot be optimised away.
    private static int s_sink;

    public static TimingTarget Leaky { get; } = Compare("selfcheck-leaky", "early-exit-compare", LeakyEquals);

    public static TimingTarget ConstantTime { get; } = Compare("selfcheck-ct", "FixedTimeEquals", FixedTime);

    public static IEnumerable<TimingTarget> Targets() => [Leaky, ConstantTime];

    // Fixed class equals the reference (full scan); random class differs at the first byte (immediate exit).
    private static TimingTarget Compare(string primitive, string operation, Func<byte[], byte[], bool> equals)
    {
        byte[] reference = RandomNumberGenerator.GetBytes(Length);
        return TimingTarget.FromBytes(primitive, operation, Length, input => s_sink += equals(input, reference) ? 1 : 0, reference);
    }

    private static bool LeakyEquals(byte[] a, byte[] b)
    {
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    private static bool FixedTime(byte[] a, byte[] b) => CryptographicOperations.FixedTimeEquals(a, b);
}
