using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Internal;

/// <summary>How a platform provides an algorithm.</summary>
internal enum Provider
{
    /// <summary>The platform's own cryptography (the BCL) does it.</summary>
    Bcl,

    /// <summary>The platform lacks it and a narrow managed fallback does it (verify-only, or constant time by construction).</summary>
    Fallback,

    /// <summary>Neither: calls throw <see cref="AlgorithmNotSupportedException"/>.</summary>
    Unsupported,
}

/// <summary>One row of the availability table.</summary>
internal readonly record struct AvailabilityRow(string Algorithm, Provider By, string Note);

/// <summary>
/// The one place that decides, per algorithm, whether the platform's cryptography, a managed fallback or nothing serves a call.
/// The order is always the platform first, then a fallback, then <see cref="AlgorithmNotSupportedException"/>. The decisions come
/// from the platform's <c>IsSupported</c> properties (and, for the few algorithms that have none, a one-time probe), never from
/// catching exceptions on a hot path. The availability table in the documentation is generated from <see cref="Availability"/>.
/// </summary>
internal static class Platform
{
    private static readonly AsyncLocal<bool> s_forceFallbacks = new();
    private static readonly Lazy<bool> s_brainpool256 = new(() => ProbeCurve(ECCurve.NamedCurves.brainpoolP256r1));
    private static readonly Lazy<bool> s_brainpool384 = new(() => ProbeCurve(ECCurve.NamedCurves.brainpoolP384r1));
    private static readonly Lazy<bool> s_brainpool512 = new(() => ProbeCurve(ECCurve.NamedCurves.brainpoolP512r1));

    /// <summary>
    /// Makes dispatch choose the managed fallback wherever one exists, for the current async flow, until the scope is disposed. For
    /// tests that run the fallbacks on hosts where the platform has the primitive.
    /// </summary>
    public static IDisposable ForceFallbacks()
    {
        s_forceFallbacks.Value = true;
        return new Scope();
    }

    private static bool Forced => s_forceFallbacks.Value;

    /// <summary>The platform has AES (every platform but the browser and WASI).</summary>
    public static bool HasAes => !IsBrowserLike;

    private static bool IsBrowserLike => OperatingSystem.IsBrowser() || OperatingSystem.IsWasi();

    /// <summary>How SHA3-224/256/384/512 is provided; <paramref name="bits"/> is the digest size. The platform has no SHA3-224.</summary>
    public static Provider Sha3(int bits)
    {
        bool bcl = bits switch
        {
            256 => SHA3_256.IsSupported,
            384 => SHA3_384.IsSupported,
            512 => SHA3_512.IsSupported,
            _ => false,
        };
        return bcl && !Forced ? Provider.Bcl : Provider.Fallback;
    }

    /// <summary>How SHAKE128 or SHAKE256 is provided.</summary>
    public static Provider Shake(int bits)
    {
        bool bcl = bits == 128 ? Shake128.IsSupported : Shake256.IsSupported;
        return bcl && !Forced ? Provider.Bcl : Provider.Fallback;
    }

    /// <summary>How ChaCha20-Poly1305 is provided.</summary>
    public static Provider ChaCha20Poly1305Support =>
        ChaCha20Poly1305.IsSupported && !Forced ? Provider.Bcl : Provider.Fallback;

    /// <summary>How RSA signature verification is provided. Signing and decryption have no fallback.</summary>
    public static Provider RsaVerify => IsBrowserLike || Forced ? Provider.Fallback : Provider.Bcl;

    /// <summary>How ECDSA verification on a curve is provided. Signing has no fallback.</summary>
    public static Provider EcdsaVerify(EcCurve curve) => curve switch
    {
        EcCurve.BrainpoolP256r1 => Probed(s_brainpool256),
        EcCurve.BrainpoolP384r1 => Probed(s_brainpool384),
        EcCurve.BrainpoolP512r1 => Probed(s_brainpool512),
        _ => IsBrowserLike || Forced ? Provider.Fallback : Provider.Bcl,
    };

    private static Provider Probed(Lazy<bool> probe) => probe.Value && !IsBrowserLike && !Forced ? Provider.Bcl : Provider.Fallback;

    // Brainpool is the one algorithm family the platform may or may not have per machine and has no IsSupported property for: it
    // is probed once per process by making a key, and the answer is kept.
    private static bool ProbeCurve(ECCurve curve)
    {
        if (IsBrowserLike)
        {
            return false;
        }

        try
        {
            using ECDsa key = ECDsa.Create(curve);
            return true;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>Creates the exception for an algorithm the platform lacks and no fallback covers.</summary>
    /// <param name="algorithm">The algorithm.</param>
    /// <param name="reason">Why, in one short sentence.</param>
    public static AlgorithmNotSupportedException NotSupported(string algorithm, string reason) =>
        new(algorithm, Describe(), reason);

    /// <summary>Throws <see cref="AlgorithmNotSupportedException"/> when the platform has no AES.</summary>
    public static void RequireAes(string algorithm)
    {
        if (!HasAes)
        {
            throw NotSupported(algorithm, "the platform has no AES");
        }
    }

    /// <summary>Throws <see cref="AlgorithmNotSupportedException"/> unless <paramref name="supported"/>.</summary>
    /// <param name="algorithm">The algorithm, as the documentation names it.</param>
    /// <param name="supported">What the platform's own <c>IsSupported</c> property says.</param>
    /// <param name="reason">Why, in one short sentence; null gives the standard sentence for this platform.</param>
    public static void Require(string algorithm, bool supported, string? reason = null)
    {
        if (!supported)
        {
            throw NotSupported(algorithm, reason ?? DefaultReason());
        }
    }

    /// <summary>Throws unless the platform has AES-GCM (the browser, and some older mobile platforms, do not).</summary>
    public static void RequireAesGcm() => Require("AES-GCM", HasAes && AesGcm.IsSupported);

    /// <summary>Throws unless the platform has AES-CCM (macOS and the browser do not).</summary>
    public static void RequireAesCcm() => Require("AES-CCM", HasAes && AesCcm.IsSupported);

    /// <summary>
    /// The typed error for a named curve the platform refused (a <see cref="PlatformNotSupportedException"/> from an import or key
    /// creation, for example Brainpool on macOS). There is no managed private-key fallback, so the operation cannot proceed.
    /// </summary>
    /// <param name="what">What was being done, for example <c>EC key import</c>.</param>
    /// <param name="cause">The platform's exception, kept as the inner exception.</param>
    public static AlgorithmNotSupportedException CurveNotSupported(string what, PlatformNotSupportedException cause) =>
        new(what + " on this curve", Describe(), "the platform lacks the curve or its parameters; private-key operations have no managed fallback", cause);

    /// <summary>Throws unless the platform has ML-KEM (FIPS 203).</summary>
    public static void RequireMlKem() => Require("ML-KEM", MLKem.IsSupported);

    /// <summary>Throws unless the platform has ML-DSA (FIPS 204).</summary>
    public static void RequireMlDsa() => Require("ML-DSA", MLDsa.IsSupported);

    /// <summary>Throws unless the platform has SLH-DSA (FIPS 205).</summary>
    public static void RequireSlhDsa() => Require("SLH-DSA", IsSlhDsaSupported());

    private static string DefaultReason() =>
        OpenSslVersion is { } v
            ? $"the loaded OpenSSL {v} does not provide it"
            : "the platform's cryptography does not provide it";

    /// <summary>Operating system and architecture, as used in the availability table's headings (for example <c>linux-x64</c>).</summary>
    public static string Rid
    {
        get
        {
            if (OperatingSystem.IsBrowser())
            {
                return "browser-wasm";
            }

            string os = OperatingSystem.IsLinux() ? "linux"
                : OperatingSystem.IsMacOS() ? "osx"
                : OperatingSystem.IsWindows() ? "win"
                : OperatingSystem.IsIOS() ? "ios"
                : OperatingSystem.IsAndroid() ? "android"
                : OperatingSystem.IsFreeBSD() ? "freebsd"
                : OperatingSystem.IsWasi() ? "wasi"
                : "other";
            return os + "-" + RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();
        }
    }

    /// <summary>The loaded OpenSSL as <c>major.minor</c> on Unix platforms that use it, or null.</summary>
    public static string? OpenSslVersion
    {
        get
        {
            if (!OperatingSystem.IsLinux() && !OperatingSystem.IsFreeBSD())
            {
                return null;
            }

            long v = SafeEvpPKeyHandle.OpenSslVersion;
            return $"{(v >> 28) & 0xF}.{(v >> 20) & 0xFF}";
        }
    }

    /// <summary>The key of this platform's section in the availability table, such as <c>linux-x64-openssl-3.0</c>.</summary>
    public static string TableKey => OpenSslVersion is { } v ? $"{Rid}-openssl-{v}" : Rid;

    /// <summary>The platform as an error message names it: <c>linux-x64, .NET 10.0.x, OpenSSL 3.0</c>.</summary>
    public static string Describe()
    {
        string text = $"{Rid}, {RuntimeInformation.FrameworkDescription}";
        if (OperatingSystem.IsWindows())
        {
            // CNG's algorithm set depends on the Windows build (post-quantum and SHA-3 arrived with specific builds).
            text += ", Windows build " + Environment.OSVersion.Version.Build.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        return OpenSslVersion is { } v ? text + ", OpenSSL " + v : text;
    }

    /// <summary>What each algorithm the library offers resolves to on this platform. The documentation's table is this list.</summary>
    public static IReadOnlyList<AvailabilityRow> Availability()
    {
        var rows = new List<AvailabilityRow>
        {
            new("SHA3-224", Sha3(224), "the platform has no SHA3-224 at all"),
            new("SHA3-256", Sha3(256), string.Empty),
            new("SHA3-384", Sha3(384), string.Empty),
            new("SHA3-512", Sha3(512), string.Empty),
            new("SHAKE128", Shake(128), string.Empty),
            new("SHAKE256", Shake(256), string.Empty),
            new("ChaCha20-Poly1305", ChaCha20Poly1305Support, string.Empty),
            new("RSA verify (PKCS#1 v1.5, PSS)", RsaVerify, "verify-only managed fallback where the platform cannot"),
            new("ECDSA verify P-256, P-384, P-521", EcdsaVerify(EcCurve.NistP256), "verify-only managed fallback where the platform cannot"),
            new("ECDSA verify brainpoolP256r1", EcdsaVerify(EcCurve.BrainpoolP256r1), "verify-only managed fallback where the platform cannot"),
            new("ECDSA verify brainpoolP384r1", EcdsaVerify(EcCurve.BrainpoolP384r1), "verify-only managed fallback where the platform cannot"),
            new("ECDSA verify brainpoolP512r1", EcdsaVerify(EcCurve.BrainpoolP512r1), "verify-only managed fallback where the platform cannot"),
            new("AES (ECB, CBC, GCM), and OCB, EAX and key wrap over it", HasAes ? Provider.Bcl : Provider.Unsupported, string.Empty),
            new("AES-GCM (CMS AuthEnvelopedData, PKCS #8 and OpenSSH keys)", HasAes && AesGcm.IsSupported ? Provider.Bcl : Provider.Unsupported, string.Empty),
            new("AES-CCM (CMS AuthEnvelopedData when asked for)", HasAes && AesCcm.IsSupported ? Provider.Bcl : Provider.Unsupported, string.Empty),
            new("RSA sign, decrypt", NoFallback(!IsBrowserLike), "no fallback: private-key operations are never done in managed code"),
            new("ECDSA, ECDH sign and agree", NoFallback(!IsBrowserLike), "no fallback: private-key operations are never done in managed code"),
            new("ML-KEM", NoFallback(MLKem.IsSupported), "no fallback"),
            new("ML-DSA", NoFallback(MLDsa.IsSupported), "no fallback"),
            new("SLH-DSA", NoFallback(IsSlhDsaSupported()), "no fallback; the platform's API is a preview"),
        };
        return rows;
    }

    /// <summary>
    /// This platform's section of the availability table in the documentation: a heading, one row per algorithm, between comment
    /// markers the drift check looks for. Lines end in <c>\n</c>.
    /// </summary>
    public static string AvailabilitySection()
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("<!-- platform: ").Append(TableKey).Append(" -->\n");
        sb.Append("### ").Append(TableKey).Append("\n\n");
        sb.Append("| Algorithm | Provided by | Note |\n| --- | --- | --- |\n");
        foreach (AvailabilityRow row in Availability())
        {
            string by = row.By switch
            {
                Provider.Bcl => "platform",
                Provider.Fallback => "managed fallback",
                _ => "not supported",
            };
            sb.Append("| ").Append(row.Algorithm).Append(" | ").Append(by).Append(" | ").Append(row.Note).Append(" |\n");
        }

        sb.Append("<!-- end -->\n");
        return sb.ToString();
    }

    private static Provider NoFallback(bool bcl) => bcl ? Provider.Bcl : Provider.Unsupported;

    // The platform's SLH-DSA API is marked experimental (SYSLIB5006); the single use is this probe, which is one property read.
#pragma warning disable SYSLIB5006
    private static bool IsSlhDsaSupported() => SlhDsa.IsSupported;
#pragma warning restore SYSLIB5006

    private sealed class Scope : IDisposable
    {
        public void Dispose() => s_forceFallbacks.Value = false;
    }
}

/// <summary>The elliptic curves the verify-only ECDSA fallback knows.</summary>
internal enum EcCurve
{
    /// <summary>NIST P-256 (secp256r1), FIPS 186-5.</summary>
    NistP256,

    /// <summary>NIST P-384 (secp384r1).</summary>
    NistP384,

    /// <summary>NIST P-521 (secp521r1).</summary>
    NistP521,

    /// <summary>brainpoolP256r1, RFC 5639.</summary>
    BrainpoolP256r1,

    /// <summary>brainpoolP384r1.</summary>
    BrainpoolP384r1,

    /// <summary>brainpoolP512r1.</summary>
    BrainpoolP512r1,
}
