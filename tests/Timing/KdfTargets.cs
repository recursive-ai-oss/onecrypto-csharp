using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Timing;

/// <summary>
/// Password-hashing targets: fixed password against a fresh random one, everything else (salt, parameters) equal.
/// Argon2i addresses memory from public values only, and the first half of Argon2id's first pass does too, so those must show
/// no difference. Argon2d, scrypt and the later part of Argon2id choose addresses from the data by design and are not claimed.
/// The memory is small (64 KiB) so that a single call is short enough for hundreds of thousands of samples.
/// </summary>
internal static class KdfTargets
{
    private static readonly byte[] Salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    private static readonly byte[] Tag = new byte[32];

    // Written so the derivation cannot be optimised away.
    private static int s_sink;

    public static IEnumerable<TimingTarget> Targets() =>
    [
        TimingTarget.FromBytes("Argon2i", "derive-passes1-64KiB", 32, password => Argon2Run(Argon2Type.Argon2i, password)),
        TimingTarget.FromBytes("Argon2id", "derive-passes1-64KiB", 32, password => Argon2Run(Argon2Type.Argon2id, password)),
        TimingTarget.FromBytes("BcryptPbkdf", "derive-rounds1", 32, password =>
        {
            BcryptPbkdf.DeriveKey(password, Salt, 1, Tag);
            s_sink += Tag[0];
        }),
    ];

    private static void Argon2Run(Argon2Type type, byte[] password)
    {
        Argon2.DeriveKey(type, password, Salt, 64, 1, 1, Tag);
        s_sink += Tag[0];
    }
}
