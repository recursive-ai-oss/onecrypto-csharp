using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>What was wrong with an Argon2 PHC string.</summary>
public enum Argon2PhcError
{
    /// <summary>The string is empty, too long, or does not have the <c>$id$v=…$params$salt$hash</c> shape.</summary>
    Malformed,

    /// <summary>The identifier is not <c>argon2d</c>, <c>argon2i</c> or <c>argon2id</c>.</summary>
    UnknownAlgorithm,

    /// <summary>The version is missing or is not 19 (0x13), the only version of RFC 9106.</summary>
    UnsupportedVersion,

    /// <summary>A parameter is missing, repeated, out of order, not plain decimal, or outside the range RFC 9106 §3.1 allows.</summary>
    BadParameter,

    /// <summary>The salt or hash is not canonical unpadded standard Base64, or is shorter than RFC 9106 allows.</summary>
    BadEncoding,

    /// <summary>The string carries something this library does not take (the optional <c>keyid</c> and <c>data</c> parameters).</summary>
    Unsupported,
}

/// <summary>Raised by <see cref="Argon2Phc.Parse(string)"/> for a string that is not a well-formed Argon2 PHC string.</summary>
public sealed class Argon2PhcFormatException : FormatException
{
    /// <summary>Creates the exception.</summary>
    public Argon2PhcFormatException(Argon2PhcError error, string message)
        : base(message) => Error = error;

    /// <summary>What was wrong.</summary>
    public Argon2PhcError Error { get; }
}

/// <summary>The fields of an Argon2 PHC string: <c>$argon2id$v=19$m=65536,t=2,p=1$salt$hash</c>.</summary>
public sealed class Argon2PhcHash
{
    /// <summary>Creates the value; no range checking beyond what <see cref="Argon2Phc.Format(Argon2PhcHash)"/> does.</summary>
    public Argon2PhcHash(Argon2Type type, int memoryKiB, int passes, int parallelism, byte[] salt, byte[] hash)
    {
        Type = type;
        MemoryKiB = memoryKiB;
        Passes = passes;
        Parallelism = parallelism;
        Salt = salt ?? throw new ArgumentNullException(nameof(salt));
        Hash = hash ?? throw new ArgumentNullException(nameof(hash));
    }

    /// <summary>The variant.</summary>
    public Argon2Type Type { get; }

    /// <summary>m, memory in KiB.</summary>
    public int MemoryKiB { get; }

    /// <summary>t, passes.</summary>
    public int Passes { get; }

    /// <summary>p, lanes.</summary>
    public int Parallelism { get; }

    /// <summary>The salt bytes.</summary>
    public byte[] Salt { get; }

    /// <summary>The tag bytes (the password hash).</summary>
    public byte[] Hash { get; }
}

/// <summary>
/// The Argon2 PHC string format: <c>$argon2id$v=19$m=…,t=…,p=…$salt$hash</c>, with salt and hash in standard Base64 without padding
/// (C2SP phc-strings; the parameters and ranges are those of RFC 9106 §3.1).
/// </summary>
/// <remarks>
/// Parsing is strict: the version must be present and 19, the parameters must be exactly <c>m</c>, <c>t</c>, <c>p</c> in that order
/// as plain decimals without sign or leading zeros, and Base64 must be canonical (no padding, no stray bits). Anything else raises
/// <see cref="Argon2PhcFormatException"/> with an <see cref="Argon2PhcError"/>; <see cref="TryParse"/> returns false instead.
/// </remarks>
public static class Argon2Phc
{
    /// <summary>Strings longer than this are refused before any parsing; a real one is under 200 characters.</summary>
    public const int MaxLength = 1024;

    /// <summary>Writes the PHC string for <paramref name="value"/>.</summary>
    /// <exception cref="ArgumentException">A field is outside the range RFC 9106 §3.1 allows (salt under 8 bytes, tag under 4, m under 8p, t or p under 1).</exception>
    public static string Format(Argon2PhcHash value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Type is not (Argon2Type.Argon2d or Argon2Type.Argon2i or Argon2Type.Argon2id))
        {
            throw new ArgumentException("Unknown Argon2 type.", nameof(value));
        }

        if (value.Passes < 1 || value.Parallelism < 1 || value.Parallelism > (1 << 24) - 1 || value.MemoryKiB < 8L * value.Parallelism)
        {
            throw new ArgumentException("Argon2 parameters are outside the ranges of RFC 9106 §3.1.", nameof(value));
        }

        if (value.Salt.Length < 8 || value.Hash.Length < 4)
        {
            throw new ArgumentException("The Argon2 salt must be at least 8 bytes and the tag at least 4.", nameof(value));
        }

        return string.Create(CultureInfo.InvariantCulture, $"${Id(value.Type)}$v=19$m={value.MemoryKiB},t={value.Passes},p={value.Parallelism}${B64(value.Salt)}${B64(value.Hash)}");
    }

    /// <summary>Hashes <paramref name="password"/> with a fresh random salt and returns the PHC string.</summary>
    /// <param name="type">The variant; Argon2id is what RFC 9106 §4 recommends.</param>
    /// <param name="password">The password.</param>
    /// <param name="memoryKiB">m in KiB.</param>
    /// <param name="passes">t.</param>
    /// <param name="parallelism">p.</param>
    /// <param name="saltLength">Salt length in bytes, 8 or more; default 16.</param>
    /// <param name="tagLength">Tag length in bytes, 4 or more; default 32.</param>
    /// <param name="limits">Cost bounds; <see cref="KdfLimits.Default"/> when null.</param>
    public static string Hash(Argon2Type type, ReadOnlySpan<byte> password, int memoryKiB, int passes, int parallelism, int saltLength = 16, int tagLength = 32, KdfLimits? limits = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(saltLength, 8);
        byte[] salt = RandomNumberGenerator.GetBytes(saltLength);
        byte[] tag = Argon2.DeriveKey(type, password, salt, memoryKiB, passes, parallelism, tagLength, limits: limits);
        return Format(new Argon2PhcHash(type, memoryKiB, passes, parallelism, salt, tag));
    }

    /// <summary>Parses a PHC string.</summary>
    /// <exception cref="Argon2PhcFormatException">The string is not a well-formed Argon2 PHC string.</exception>
    public static Argon2PhcHash Parse(string phc)
    {
        ArgumentNullException.ThrowIfNull(phc);
        if (phc.Length == 0 || phc.Length > MaxLength)
        {
            throw new Argon2PhcFormatException(Argon2PhcError.Malformed, "The PHC string is empty or too long.");
        }

        if (phc[0] != '$')
        {
            throw new Argon2PhcFormatException(Argon2PhcError.Malformed, "A PHC string starts with '$'.");
        }

        string[] f = phc.Split('$');
        // "" id v params salt hash; without a version field the string means the obsolete version 0x10.
        if (f.Length == 5 && f[2].StartsWith("m=", StringComparison.Ordinal))
        {
            throw new Argon2PhcFormatException(Argon2PhcError.UnsupportedVersion, "The version field v=19 is required.");
        }

        if (f.Length != 6)
        {
            throw new Argon2PhcFormatException(Argon2PhcError.Malformed, "Expected $id$v=19$m=…,t=…,p=…$salt$hash.");
        }

        Argon2Type type = f[1] switch
        {
            "argon2d" => Argon2Type.Argon2d,
            "argon2i" => Argon2Type.Argon2i,
            "argon2id" => Argon2Type.Argon2id,
            _ => throw new Argon2PhcFormatException(Argon2PhcError.UnknownAlgorithm, "The identifier is not argon2d, argon2i or argon2id."),
        };

        if (f[2] != "v=19")
        {
            throw new Argon2PhcFormatException(Argon2PhcError.UnsupportedVersion, "Only version 19 (0x13) is supported.");
        }

        string[] ps = f[3].Split(',');
        if (ps.Length != 3)
        {
            throw new Argon2PhcFormatException(f[3].Contains("keyid=", StringComparison.Ordinal) || f[3].Contains("data=", StringComparison.Ordinal) ? Argon2PhcError.Unsupported : Argon2PhcError.BadParameter, "Expected exactly m, t and p.");
        }

        int m = Param(ps[0], "m=");
        int t = Param(ps[1], "t=");
        int p = Param(ps[2], "p=");
        // RFC 9106 §3.1: p in [1, 2^24-1], t >= 1, m >= 8p.
        if (t < 1 || p < 1 || p > (1 << 24) - 1 || m < 8L * p)
        {
            throw new Argon2PhcFormatException(Argon2PhcError.BadParameter, "A parameter is outside the range RFC 9106 §3.1 allows.");
        }

        byte[] salt = Unb64(f[4]);
        byte[] hash = Unb64(f[5]);
        if (salt.Length < 8 || hash.Length < 4)
        {
            throw new Argon2PhcFormatException(Argon2PhcError.BadEncoding, "The salt must be at least 8 bytes and the hash at least 4.");
        }

        return new Argon2PhcHash(type, m, t, p, salt, hash);
    }

    /// <summary>Parses a PHC string; false (and null <paramref name="value"/>) when it is not well formed.</summary>
    public static bool TryParse(string? phc, out Argon2PhcHash? value)
    {
        value = null;
        if (phc is null)
        {
            return false;
        }

        try
        {
            value = Parse(phc);
            return true;
        }
        catch (Argon2PhcFormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Checks <paramref name="password"/> against a PHC string: recomputes the tag with the string's parameters and compares it in
    /// constant time. Returns false for a wrong password.
    /// </summary>
    /// <exception cref="Argon2PhcFormatException">The string is malformed.</exception>
    /// <exception cref="KdfLimitExceededException">The string's cost exceeds <paramref name="limits"/> (<see cref="KdfLimits.Default"/> when null); checked before any memory is allocated.</exception>
    public static bool Verify(ReadOnlySpan<byte> password, string phc, KdfLimits? limits = null)
    {
        Argon2PhcHash h = Parse(phc);
        return Argon2.Verify(h.Type, password, h.Salt, h.MemoryKiB, h.Passes, h.Parallelism, h.Hash, limits: limits);
    }

    private static string Id(Argon2Type t) => t switch
    {
        Argon2Type.Argon2d => "argon2d",
        Argon2Type.Argon2i => "argon2i",
        _ => "argon2id",
    };

    private static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=');

    private static int Param(string s, string name)
    {
        if (!s.StartsWith(name, StringComparison.Ordinal))
        {
            throw new Argon2PhcFormatException(Argon2PhcError.BadParameter, $"Expected parameter {name[0]}.");
        }

        ReadOnlySpan<char> v = s.AsSpan(name.Length);
        // Plain decimal: digits only, no sign, no leading zero, at most 9 digits so it fits an int.
        if (v.Length is 0 or > 9 || (v[0] == '0' && v.Length > 1))
        {
            throw new Argon2PhcFormatException(Argon2PhcError.BadParameter, $"Parameter {name[0]} is not a plain decimal.");
        }

        foreach (char c in v)
        {
            if (c is < '0' or > '9')
            {
                throw new Argon2PhcFormatException(Argon2PhcError.BadParameter, $"Parameter {name[0]} is not a plain decimal.");
            }
        }

        return int.Parse(v, NumberStyles.None, CultureInfo.InvariantCulture);
    }

    // Unpadded standard Base64 with zero trailing bits: decode, re-encode, require the same text.
    private static byte[] Unb64(string s)
    {
        if (s.Length == 0 || s.Length % 4 == 1)
        {
            throw new Argon2PhcFormatException(Argon2PhcError.BadEncoding, "Not valid unpadded Base64.");
        }

        foreach (char c in s)
        {
            bool ok = c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '+' or '/';
            if (!ok)
            {
                throw new Argon2PhcFormatException(Argon2PhcError.BadEncoding, "Not valid unpadded Base64.");
            }
        }

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(s + new string('=', (4 - (s.Length % 4)) % 4));
        }
        catch (FormatException)
        {
            throw new Argon2PhcFormatException(Argon2PhcError.BadEncoding, "Not valid unpadded Base64.");
        }

        if (!string.Equals(B64(bytes), s, StringComparison.Ordinal))
        {
            throw new Argon2PhcFormatException(Argon2PhcError.BadEncoding, "Base64 is not canonical.");
        }

        return bytes;
    }
}
