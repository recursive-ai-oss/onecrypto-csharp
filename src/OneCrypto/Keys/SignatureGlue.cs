using System.Runtime.InteropServices;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Internal;

namespace RecursiveAI.OneCrypto.Keys;

/// <summary>Signature encodings and checks shared by every backend and by two-phase completion. All inputs are public.</summary>
internal static class SignatureGlue
{
    public static SignatureVerification Verify(SignatureSpec spec, PublicKeyInfo key, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        string name = spec.ToString();
        if (!spec.FitsKey(key))
        {
            return new(SignatureStatus.KeyMismatch, name, $"{name} cannot be checked with a {key.Algorithm.Name} key.", "RFC 5280 §4.1.2.7");
        }

        switch (spec.Kind)
        {
            case SignatureKind.RsaPkcs1 or SignatureKind.RsaPss or SignatureKind.Ed25519:
                return key.VerifySignature(spec.ToAlgorithmIdentifier(key), data, signature);
            case SignatureKind.Ecdsa:
                if (spec.Format == EcdsaSignatureFormat.Rfc4754)
                {
                    if (!TryToDer(key, signature, out byte[] der))
                    {
                        return new(SignatureStatus.Invalid, name, "The P1363 signature has the wrong length for the curve.", "IEEE 1363 §E.2");
                    }

                    return key.VerifySignature(SignatureSpec.Ecdsa(spec.Hash).ToAlgorithmIdentifier(key), data, der);
                }

                return key.VerifySignature(spec.ToAlgorithmIdentifier(key), data, signature);
            case SignatureKind.Ed448 when spec.Context.IsEmpty:
            case SignatureKind.MlDsa when spec.Context.IsEmpty:
                return key.VerifySignature(spec.ToAlgorithmIdentifier(key), data, signature);
            case SignatureKind.Ed448:
                if (key.KeyAlgorithm != KeyAlgorithm.Ed448)
                {
                    return new(SignatureStatus.KeyMismatch, name, $"Ed448 needs an Ed448 key; the key is {key.Algorithm.Name}.", "RFC 8410 §3");
                }

                bool ok = key.KeyBits.Length == 57 && signature.Length == 114 && Primitives.Ed448.Verify(key.KeyBits.Span, data, spec.Context, signature);
                return ok ? new(SignatureStatus.Valid, name, string.Empty, "RFC 8032 §5.2.7") : new(SignatureStatus.Invalid, name, "The Ed448 signature does not verify.", "RFC 8032 §5.2.7");
            default:
                return VerifyMlDsaWithContext(spec, key, data, signature, name);
        }
    }

    private static SignatureVerification VerifyMlDsaWithContext(SignatureSpec spec, PublicKeyInfo key, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, string name)
    {
        if (key.KeyAlgorithm != KeyAlgorithm.MlDsa)
        {
            return new(SignatureStatus.KeyMismatch, name, $"ML-DSA needs an ML-DSA key; the key is {key.Algorithm.Name}.", "RFC 9881 §4");
        }

        if (!MLDsa.IsSupported)
        {
            return new(SignatureStatus.AlgorithmNotSupported, name, $"ML-DSA is not available on {RuntimeInformation.OSDescription}.", "FIPS 204");
        }

        try
        {
            MLDsaAlgorithm which = key.Algorithm.Oid switch { KnownOids.MlDsa44 => MLDsaAlgorithm.MLDsa44, KnownOids.MlDsa65 => MLDsaAlgorithm.MLDsa65, _ => MLDsaAlgorithm.MLDsa87 };
            using MLDsa k = MLDsa.ImportMLDsaPublicKey(which, key.KeyBits.Span);
            return k.VerifyData(data, signature, spec.Context)
                ? new(SignatureStatus.Valid, name, string.Empty, "FIPS 204 §5.3")
                : new(SignatureStatus.Invalid, name, "The ML-DSA signature does not verify.", "FIPS 204 §5.3");
        }
        catch (CryptographicException e)
        {
            return new(SignatureStatus.Invalid, name, "The platform could not check the signature: " + e.Message, "FIPS 204 §5.3");
        }
    }

    /// <summary>Checks a signature over a digest the caller computed (RSA and ECDSA only).</summary>
    public static SignatureVerification VerifyDigest(SignatureSpec spec, PublicKeyInfo key, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
    {
        string name = spec.ToString();
        if (!spec.SignsDigest)
        {
            return new(SignatureStatus.AlgorithmNotSupported, name, "This scheme signs the message, not a digest.", "RFC 8032 §5.1.6");
        }

        if (digest.Length != SignatureSpec.DigestSize(spec.Hash))
        {
            return new(SignatureStatus.Malformed, name, "The digest length does not match the hash.", "RFC 8017 §9.2");
        }

        try
        {
            if (spec.Kind == SignatureKind.Ecdsa)
            {
                if (key.KeyAlgorithm != KeyAlgorithm.EllipticCurve)
                {
                    return new(SignatureStatus.KeyMismatch, name, $"ECDSA needs an EC key; the key is {key.Algorithm.Name}.", "RFC 5480 §2.1.1");
                }

                using ECDsa ec = key.ToECDsa();
                bool ecOk = ec.VerifyHash(digest, signature, spec.Format == EcdsaSignatureFormat.Der ? DSASignatureFormat.Rfc3279DerSequence : DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                return ecOk ? new(SignatureStatus.Valid, name, string.Empty, "FIPS 186-5 §6.4.2") : new(SignatureStatus.Invalid, name, "The ECDSA signature does not verify.", "FIPS 186-5 §6.4.2");
            }

            if (key.KeyAlgorithm is not (KeyAlgorithm.Rsa or KeyAlgorithm.RsaPss))
            {
                return new(SignatureStatus.KeyMismatch, name, $"RSA signatures need an RSA key; the key is {key.Algorithm.Name}.", "RFC 8017 §8");
            }

            var kr = new Asn1Reader(key.KeyBits.Span, Asn1Rules.Ber);
            Asn1Reader ks = kr.ReadSequence();
            ReadOnlySpan<byte> modulus = ks.ReadUnsignedIntegerBytes();
            ReadOnlySpan<byte> exponent = ks.ReadUnsignedIntegerBytes();
            bool ok = spec.Kind == SignatureKind.RsaPkcs1
                ? PlatformSignatures.RsaVerifyPkcs1(modulus, exponent, spec.Hash, digest, signature)
                : PlatformSignatures.RsaVerifyPss(modulus, exponent, spec.Hash, spec.Hash, digest.Length, digest, signature);
            return ok ? new(SignatureStatus.Valid, name, string.Empty, "RFC 8017 §8.2.2") : new(SignatureStatus.Invalid, name, "The RSA signature does not verify.", "RFC 8017 §8.2.2");
        }
        catch (Asn1ParseException e)
        {
            return new(SignatureStatus.Malformed, name, "The key could not be decoded: " + e.Message, "RFC 5280 §4.1.2.7");
        }
        catch (ArgumentException e)
        {
            return new(SignatureStatus.Malformed, name, e.Message, "RFC 5280 §4.1.2.7");
        }
        catch (NotSupportedException e)
        {
            return new(SignatureStatus.AlgorithmNotSupported, name, e.Message, "RFC 5280 §4.1.2.7");
        }
        catch (CryptographicException e)
        {
            return new(SignatureStatus.Invalid, name, "The platform could not check the signature: " + e.Message, "RFC 8017 §8.2.2");
        }
    }

    /// <summary>Converts a fixed-width <c>r || s</c> signature to the DER SEQUENCE; false when its length does not fit the curve.</summary>
    public static bool TryToDer(PublicKeyInfo key, ReadOnlySpan<byte> p1363, out byte[] der)
    {
        int size = (key.KeySizeBits + 7) / 8;
        if (size == 0 || p1363.Length != 2 * size)
        {
            der = [];
            return false;
        }

        der = DerWriter.Sequence(DerWriter.UnsignedInteger(p1363[..size]), DerWriter.UnsignedInteger(p1363[size..]));
        return true;
    }

    /// <summary>Converts a DER ECDSA signature to the fixed-width form for a curve of <paramref name="size"/>-octet scalars.</summary>
    public static byte[] DerToP1363(ReadOnlySpan<byte> der, int size)
    {
        var r = new Asn1Reader(der, Asn1Rules.Der);
        Asn1Reader seq = r.ReadSequence();
        ReadOnlySpan<byte> a = seq.ReadUnsignedIntegerBytes();
        ReadOnlySpan<byte> b = seq.ReadUnsignedIntegerBytes();
        var o = new byte[2 * size];
        a.CopyTo(o.AsSpan(size - a.Length, a.Length));
        b.CopyTo(o.AsSpan((2 * size) - b.Length, b.Length));
        return o;
    }
}
