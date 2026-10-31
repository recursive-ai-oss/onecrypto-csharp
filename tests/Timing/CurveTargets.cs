using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Timing;

/// <summary>
/// Timing targets for the curve primitives. The secret is the private seed or scalar; the message, context and peer point
/// are public and fixed, so any timing difference between the classes comes from the secret.
/// </summary>
internal static class CurveTargets
{
    private static int s_sink;

    public static IEnumerable<TimingTarget> Targets()
    {
        byte[] message = RandomNumberGenerator.GetBytes(64);
        // A peer point that is not the base point, so the ladder runs on a generic u.
        byte[] peer25519 = RandomNumberGenerator.GetBytes(32);
        peer25519[31] &= 0x7f;
        byte[] peer448 = RandomNumberGenerator.GetBytes(56);
        peer448[55] = 0;

        yield return TimingTarget.FromBytes("Ed25519", "sign", 32, seed =>
        {
            Span<byte> sig = stackalloc byte[64];
            Ed25519.TrySign(seed, message, sig, out int n);
            s_sink += sig[0] + n;
        });
        yield return TimingTarget.FromBytes("Ed448", "sign", 57, seed =>
        {
            Span<byte> sig = stackalloc byte[114];
            Ed448.TrySign(seed, message, default, sig, out int n);
            s_sink += sig[0] + n;
        });
        yield return TimingTarget.FromBytes("X25519", "scalar-multiply", 32, k =>
        {
            Span<byte> r = stackalloc byte[32];
            X25519.ScalarMult(k, peer25519, r);
            s_sink += r[0];
        });
        yield return TimingTarget.FromBytes("X25519", "base-multiply", 32, k =>
        {
            Span<byte> r = stackalloc byte[32];
            X25519.DerivePublicKey(k, r);
            s_sink += r[0];
        });
        yield return TimingTarget.FromBytes("X448", "scalar-multiply", 56, k =>
        {
            Span<byte> r = stackalloc byte[56];
            X448.ScalarMult(k, peer448, r);
            s_sink += r[0];
        });
        yield return TimingTarget.FromBytes("X448", "base-multiply", 56, k =>
        {
            Span<byte> r = stackalloc byte[56];
            X448.DerivePublicKey(k, r);
            s_sink += r[0];
        });
    }
}
