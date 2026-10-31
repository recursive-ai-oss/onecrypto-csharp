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

    // SLH-DSA is still marked experimental in the platform API, so it is not used; the answer says so.
    public static SignatureVerification VerifySlhDsa(PublicKeyInfo key, AlgorithmIdentifier alg, ReadOnlySpan<byte> data, ReadOnlySpan<byte> sig, string name) =>
        key.Algorithm.Oid != alg.Oid
            ? new(SignatureStatus.KeyMismatch, name, $"{name} needs an {name} key; the key is {key.Algorithm.Name}.", "RFC 9909")
            : new(SignatureStatus.AlgorithmNotSupported, name, $"SLH-DSA is only an experimental API on {RuntimeInformation.OSDescription}.", "FIPS 205");
}
