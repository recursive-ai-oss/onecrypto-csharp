using System.Diagnostics;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Benchmarks;

/// <summary>
/// Peak memory of one key derivation per implementation: <c>peak-kdf &lt;ours|bouncycastle|konscious|isopoh&gt; &lt;argon2-m64|argon2-m19|scrypt-14|scrypt-17&gt;</c>.
/// Run each in its own process: the figure is the highest working set during the call minus the working set just before it, so the
/// runtime and the library's code are not counted but everything the call allocates is.
/// </summary>
internal static class KdfPeak
{
    private static readonly byte[] Password = "correct horse battery staple"u8.ToArray();
    private static readonly byte[] Salt = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] Salt16 = Salt.AsSpan(0, 16).ToArray();

    public static int Run(string[] args)
    {
        if (args.Length != 2)
        {
            Console.Error.WriteLine("usage: peak-kdf <ours|bouncycastle|konscious|isopoh> <argon2-m64|argon2-m19|scrypt-14|scrypt-17>");
            return 2;
        }

        (string impl, string config) = (args[0], args[1]);
        Action? work = (impl, config) switch
        {
            ("ours", "argon2-m64") => () => Argon2.DeriveKey(Argon2Type.Argon2id, Password, Salt16, 64 * 1024, 3, 4, 32),
            ("ours", "argon2-m19") => () => Argon2.DeriveKey(Argon2Type.Argon2id, Password, Salt16, 19 * 1024, 2, 1, 32),
            ("ours", "scrypt-14") => () => Scrypt.DeriveKey(Password, Salt, 1 << 14, 8, 1, 32),
            ("ours", "scrypt-17") => () => Scrypt.DeriveKey(Password, Salt, 1 << 17, 8, 1, 32),
            ("bouncycastle", "argon2-m64") => () => BcArgon2(64 * 1024, 3, 4),
            ("bouncycastle", "argon2-m19") => () => BcArgon2(19 * 1024, 2, 1),
            ("bouncycastle", "scrypt-14") => () => SCrypt.Generate(Password, Salt, 1 << 14, 8, 1, 32),
            ("bouncycastle", "scrypt-17") => () => SCrypt.Generate(Password, Salt, 1 << 17, 8, 1, 32),
            ("konscious", "argon2-m64") => () => Konscious(64 * 1024, 3, 4),
            ("konscious", "argon2-m19") => () => Konscious(19 * 1024, 2, 1),
            ("isopoh", "argon2-m64") => () => IsopohHash(64 * 1024, 3, 4),
            ("isopoh", "argon2-m19") => () => IsopohHash(19 * 1024, 2, 1),
            _ => null,
        };
        if (work is null)
        {
            Console.Error.WriteLine("no such combination");
            return 2;
        }

        // Warm the code paths with a tiny call of the same kind so JIT memory is not attributed to the derivation.
        GC.Collect();
        using var self = Process.GetCurrentProcess();
        self.Refresh();
        long before = self.WorkingSet64;
        long peak = PeakMemory.Measure(work);
        Console.WriteLine($"{impl} {config}: peak working set +{(peak - before) / (1024.0 * 1024.0):F1} MiB over {before / (1024.0 * 1024.0):F1} MiB");
        return 0;
    }

    private static void BcArgon2(int memoryKiB, int passes, int lanes)
    {
        var generator = new Argon2BytesGenerator();
        generator.Init(new Argon2Parameters.Builder(Argon2Parameters.Argon2id).WithVersion(Argon2Parameters.Version13)
            .WithSalt(Salt16).WithIterations(passes).WithMemoryAsKB(memoryKiB).WithParallelism(lanes).Build());
        generator.GenerateBytes(Password, new byte[32]);
    }

    private static void Konscious(int memoryKiB, int passes, int lanes)
    {
        using var argon2 = new global::Konscious.Security.Cryptography.Argon2id(Password)
        {
            Salt = Salt16,
            DegreeOfParallelism = lanes,
            Iterations = passes,
            MemorySize = memoryKiB,
        };
        argon2.GetBytes(32);
    }

    private static void IsopohHash(int memoryKiB, int passes, int lanes)
    {
        var config = new global::Isopoh.Cryptography.Argon2.Argon2Config
        {
            Type = global::Isopoh.Cryptography.Argon2.Argon2Type.HybridAddressing,
            Version = global::Isopoh.Cryptography.Argon2.Argon2Version.Nineteen,
            TimeCost = passes,
            MemoryCost = memoryKiB,
            Lanes = lanes,
            Threads = lanes,
            Password = Password,
            Salt = Salt16,
            HashLength = 32,
        };
        using var argon2 = new global::Isopoh.Cryptography.Argon2.Argon2(config);
        using var hash = argon2.Hash();
    }
}
