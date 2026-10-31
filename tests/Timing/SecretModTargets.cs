using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Internal;

namespace OneCrypto.Timing;

/// <summary>
/// The reduction that rebuilds an RSA key's CRT exponents (d mod p-1) when a key file omits them. The secret is the 256-byte value;
/// the 128-byte modulus is the same in both classes. Fixed against fresh random value.
/// </summary>
internal static class SecretModTargets
{
    private static readonly byte[] Modulus = MakeModulus();
    private static readonly byte[] Result = new byte[128];

    // Written so the reduction cannot be optimised away.
    private static int s_sink;

    public static IEnumerable<TimingTarget> Targets() =>
    [
        TimingTarget.FromBytes("SecretMod", "reduce-2048-by-1024", 256, value =>
        {
            SecretMod.Reduce(value, Modulus, Result);
            s_sink += Result[0];
        }),
    ];

    private static byte[] MakeModulus()
    {
        byte[] m = RandomNumberGenerator.GetBytes(128);
        m[0] |= 0x80;
        m[^1] |= 1;
        return m;
    }
}
