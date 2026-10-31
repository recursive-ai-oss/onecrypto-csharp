using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto;

/// <summary>ML-DSA and SLH-DSA verification through the platform, where it has them.</summary>
internal static class PostQuantum
{
    public static SignatureVerification VerifyMlDsa(PublicKeyInfo key, AlgorithmIdentifier alg, ReadOnlySpan<byte> data, ReadOnlySpan<byte> sig, string name)
    {
        if (key.Algorithm.Oid != alg.Oid)
        {
            return new(SignatureStatus.KeyMismatch, name, $"{name} needs an {name} key; the key is {key.Algorithm.Name}.", "RFC 9881");
        }

        if (!MLDsa.IsSupported)
        {
            return new(SignatureStatus.AlgorithmNotSupported, name, $"ML-DSA is not available on {RuntimeInformation.OSDescription}.", "FIPS 204");
        }

        MLDsaAlgorithm which = alg.Oid switch { KnownOids.MlDsa44 => MLDsaAlgorithm.MLDsa44, KnownOids.MlDsa65 => MLDsaAlgorithm.MLDsa65, _ => MLDsaAlgorithm.MLDsa87 };
        using MLDsa k = MLDsa.ImportMLDsaPublicKey(which, key.KeyBits.Span);
        return k.VerifyData(data, sig)
            ? new(SignatureStatus.Valid, name, string.Empty, "RFC 9881")
            : new(SignatureStatus.Invalid, name, "The ML-DSA signature does not verify.", "RFC 9881");
    }

    /// <summary>
    /// SLH-DSA verification through the platform's SlhDsa, preview while that API is experimental. Reported with a
    /// "(preview)" reference so callers can tell.
    /// </summary>
    public static SignatureVerification VerifySlhDsa(PublicKeyInfo key, AlgorithmIdentifier alg, ReadOnlySpan<byte> data, ReadOnlySpan<byte> sig, string name)
    {
        if (key.Algorithm.Oid != alg.Oid)
        {
            return new(SignatureStatus.KeyMismatch, name, $"{name} needs an {name} key; the key is {key.Algorithm.Name}.", "RFC 9909");
        }

        return VerifySlhDsaCore(key, alg, data, sig, name);
    }

#pragma warning disable SYSLIB5006 // The platform SlhDsa is experimental; this is the only file that touches it, and results say preview.
    private static SignatureVerification VerifySlhDsaCore(PublicKeyInfo key, AlgorithmIdentifier alg, ReadOnlySpan<byte> data, ReadOnlySpan<byte> sig, string name)
    {
        const string Ref = "RFC 9909 (preview)";
        if (!SlhDsa.IsSupported)
        {
            return new(SignatureStatus.AlgorithmNotSupported, name, $"SLH-DSA is not available on {RuntimeInformation.OSDescription}.", "FIPS 205");
        }

        // RFC 9909 §3 object identifiers 2.16.840.1.101.3.4.3.20 to .31, in the order of FIPS 205 Table 2.
        SlhDsaAlgorithm? which = alg.Oid[^2..] switch
        {
            "20" => SlhDsaAlgorithm.SlhDsaSha2_128s,
            "21" => SlhDsaAlgorithm.SlhDsaSha2_128f,
            "22" => SlhDsaAlgorithm.SlhDsaSha2_192s,
            "23" => SlhDsaAlgorithm.SlhDsaSha2_192f,
            "24" => SlhDsaAlgorithm.SlhDsaSha2_256s,
            "25" => SlhDsaAlgorithm.SlhDsaSha2_256f,
            "26" => SlhDsaAlgorithm.SlhDsaShake128s,
            "27" => SlhDsaAlgorithm.SlhDsaShake128f,
            "28" => SlhDsaAlgorithm.SlhDsaShake192s,
            "29" => SlhDsaAlgorithm.SlhDsaShake192f,
            "30" => SlhDsaAlgorithm.SlhDsaShake256s,
            "31" => SlhDsaAlgorithm.SlhDsaShake256f,
            _ => null,
        };
        if (which is null)
        {
            return new(SignatureStatus.AlgorithmNotSupported, name, "Unknown SLH-DSA parameter set.", Ref);
        }

        if (key.KeyBits.Length != which.PublicKeySizeInBytes)
        {
            return new(SignatureStatus.Invalid, name, "The SLH-DSA public key has the wrong length.", Ref);
        }

        using SlhDsa k = SlhDsa.ImportSlhDsaPublicKey(which, key.KeyBits.Span);
        return k.VerifyData(data, sig)
            ? new(SignatureStatus.Valid, name, string.Empty, Ref)
            : new(SignatureStatus.Invalid, name, "The SLH-DSA signature does not verify.", Ref);
    }
#pragma warning restore SYSLIB5006
}
