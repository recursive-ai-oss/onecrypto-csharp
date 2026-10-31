using System.Runtime.InteropServices;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Internal;

namespace RecursiveAI.OneCrypto;

/// <summary>What a signature algorithm identifier asks for: the signature family and its hash.</summary>
internal readonly record struct SignatureScheme(string Family, HashAlgorithmName Hash, string HashOid, PssParameters? Pss);

/// <summary>RSASSA-PSS-params (RFC 4055 §3.1) with the defaults applied.</summary>
internal sealed record PssParameters(string HashOid, string MgfHashOid, int SaltLength, int TrailerField)
{
    /// <summary>Reads the parameters element; absent parameters mean the SHA-1 defaults.</summary>
    public static PssParameters Parse(ReadOnlyMemory<byte> parameters)
    {
        string hash = KnownOids.Sha1, mgfHash = KnownOids.Sha1;
        int salt = 20, trailer = 1;
        if (!parameters.IsEmpty)
        {
            var o = new Asn1Reader(parameters.Span, Asn1Rules.Ber);
            Asn1Reader s = o.ReadSequence();
            o.ThrowIfNotEmpty();
            if (s.TryPeekTag(out Asn1Tag t) && t == Asn1Tag.Context(0))
            {
                Asn1Reader w = s.ReadSequence(Asn1Tag.Context(0, true));
                hash = AlgorithmIdentifier.Parse(X509Read.Slice(parameters, w.ReadEncodedValue())).Oid;
                w.ThrowIfNotEmpty();
            }

            if (s.TryPeekTag(out t) && t == Asn1Tag.Context(1))
            {
                Asn1Reader w = s.ReadSequence(Asn1Tag.Context(1, true));
                AlgorithmIdentifier mgf = AlgorithmIdentifier.Parse(X509Read.Slice(parameters, w.ReadEncodedValue()));
                w.ThrowIfNotEmpty();
                if (mgf.Oid != KnownOids.Mgf1)
                {
                    throw X509Read.Invalid("RSASSA-PSS-params", "the mask generation function is not MGF1");
                }

                mgfHash = AlgorithmIdentifier.Parse(mgf.Parameters).Oid;
            }

            if (s.TryPeekTag(out t) && t == Asn1Tag.Context(2))
            {
                Asn1Reader w = s.ReadSequence(Asn1Tag.Context(2, true));
                salt = w.ReadInt32();
                w.ThrowIfNotEmpty();
            }

            if (s.TryPeekTag(out t) && t == Asn1Tag.Context(3))
            {
                Asn1Reader w = s.ReadSequence(Asn1Tag.Context(3, true));
                trailer = w.ReadInt32();
                w.ThrowIfNotEmpty();
            }

            s.ThrowIfNotEmpty();
        }

        return new PssParameters(hash, mgfHash, salt, trailer);
    }
}

/// <summary>Maps signature algorithm identifiers to schemes and checks signatures with the platform or the library's own curves.</summary>
internal static class SignatureAlgorithms
{
    internal static bool IsComposite(string oid) =>
        oid.StartsWith("1.3.6.1.5.5.7.6.", StringComparison.Ordinal) && int.TryParse(oid.AsSpan(16), out int n) && n is >= 37 and <= 54;

    /// <summary>Hash algorithm name and OID for the digest OIDs the profile allows.</summary>
    public static bool TryHash(string oid, out HashAlgorithmName name)
    {
        switch (oid)
        {
            case KnownOids.Sha1: name = HashAlgorithmName.SHA1; return true;
            case KnownOids.Sha256: name = HashAlgorithmName.SHA256; return true;
            case KnownOids.Sha384: name = HashAlgorithmName.SHA384; return true;
            case KnownOids.Sha512: name = HashAlgorithmName.SHA512; return true;
            case KnownOids.Sha3256: name = HashAlgorithmName.SHA3_256; return true;
            case KnownOids.Sha3384: name = HashAlgorithmName.SHA3_384; return true;
            case KnownOids.Sha3512: name = HashAlgorithmName.SHA3_512; return true;
            default: name = default; return false;
        }
    }

    private static bool Supported(HashAlgorithmName h) => h.Name switch
    {
        "SHA3-256" => SHA3_256.IsSupported,
        "SHA3-384" => SHA3_384.IsSupported,
        "SHA3-512" => SHA3_512.IsSupported,
        _ => true,
    };

    /// <summary>The scheme for RSA PKCS#1 v1.5 and ECDSA identifiers (hash is part of the identifier).</summary>
    public static bool TryScheme(AlgorithmIdentifier alg, out SignatureScheme scheme)
    {
        (string family, string hashOid) = alg.Oid switch
        {
            KnownOids.Sha1WithRsa => ("rsa", KnownOids.Sha1),
            KnownOids.Sha224WithRsa => ("rsa", KnownOids.Sha224),
            KnownOids.Sha256WithRsa => ("rsa", KnownOids.Sha256),
            KnownOids.Sha384WithRsa => ("rsa", KnownOids.Sha384),
            KnownOids.Sha512WithRsa => ("rsa", KnownOids.Sha512),
            KnownOids.Md5WithRsa => ("rsa", "1.2.840.113549.2.5"),
            KnownOids.RsaSha3256 => ("rsa", KnownOids.Sha3256),
            KnownOids.RsaSha3384 => ("rsa", KnownOids.Sha3384),
            KnownOids.RsaSha3512 => ("rsa", KnownOids.Sha3512),
            KnownOids.EcdsaSha1 => ("ecdsa", KnownOids.Sha1),
            KnownOids.EcdsaSha224 => ("ecdsa", KnownOids.Sha224),
            KnownOids.EcdsaSha256 => ("ecdsa", KnownOids.Sha256),
            KnownOids.EcdsaSha384 => ("ecdsa", KnownOids.Sha384),
            KnownOids.EcdsaSha512 => ("ecdsa", KnownOids.Sha512),
            KnownOids.EcdsaSha3256 => ("ecdsa", KnownOids.Sha3256),
            KnownOids.EcdsaSha3384 => ("ecdsa", KnownOids.Sha3384),
            KnownOids.EcdsaSha3512 => ("ecdsa", KnownOids.Sha3512),
            _ => (string.Empty, string.Empty),
        };
        HashAlgorithmName h = default;
        if (family.Length == 0)
        {
            scheme = default;
            return false;
        }

        if (hashOid == "1.2.840.113549.2.5")
        {
            h = HashAlgorithmName.MD5;
        }
        else if (hashOid == KnownOids.Sha224)
        {
            h = new HashAlgorithmName("SHA224");
        }
        else
        {
            TryHash(hashOid, out h);
        }

        scheme = new SignatureScheme(family, h, hashOid, null);
        return true;
    }

    public static SignatureVerification Verify(PublicKeyInfo key, AlgorithmIdentifier alg, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        string name = alg.Name;
        SignatureVerification Fail(SignatureStatus s, string reason, string rfc) => new(s, name, reason, rfc);

        try
        {
            if (TryScheme(alg, out SignatureScheme scheme))
            {
                if (scheme.Family == "rsa")
                {
                    if (key.KeyAlgorithm != KeyAlgorithm.Rsa)
                    {
                        return Fail(SignatureStatus.KeyMismatch, $"{name} needs an rsaEncryption key; the key is {key.Algorithm.Name}.", "RFC 8017 §8.2");
                    }

                    return VerifyRsa(key, scheme, RSASignaturePadding.Pkcs1, data, signature, name);
                }

                if (key.KeyAlgorithm != KeyAlgorithm.EllipticCurve)
                {
                    return Fail(SignatureStatus.KeyMismatch, $"{name} needs an EC key; the key is {key.Algorithm.Name}.", "RFC 5480 §2.1.1");
                }

                if (!Supported(scheme.Hash))
                {
                    return Fail(SignatureStatus.AlgorithmNotSupported, $"{scheme.Hash.Name} is not available on {RuntimeInformation.OSDescription}.", "RFC 5758");
                }

                // The platform also accepts BER and unpadded integers here; the signature must be the strict DER of RFC 3279 §2.2.3.
                if (!IsStrictEcdsaSignature(signature))
                {
                    return Fail(SignatureStatus.Invalid, "The ECDSA signature is not a strict DER SEQUENCE of two positive INTEGERs.", "RFC 3279 §2.2.3");
                }

                // Where the platform lacks the curve (the browser, Brainpool on some systems) the verify-only fallback checks the signature.
                if (EcCurveOf(key.CurveOid) is EcCurve curve && Platform.EcdsaVerify(curve) != Provider.Bcl)
                {
                    byte[]? digest = PlatformHash.Digest(scheme.Hash, data);
                    if (digest is null)
                    {
                        return Fail(SignatureStatus.AlgorithmNotSupported, $"{scheme.Hash.Name} is not available on {RuntimeInformation.OSDescription}.", "RFC 5758");
                    }

                    bool fallbackOk = PlatformSignatures.EcdsaVerifyHash(curve, key.KeyBits.Span, digest, signature, DSASignatureFormat.Rfc3279DerSequence);
                    return fallbackOk ? new(SignatureStatus.Valid, name, string.Empty, "RFC 5758 §3.2") : Fail(SignatureStatus.Invalid, "The ECDSA signature does not verify.", "RFC 5758 §3.2");
                }

                using ECDsa ec = key.ToECDsa();
                bool ok = ec.VerifyData(data, signature, scheme.Hash, DSASignatureFormat.Rfc3279DerSequence);
                return ok ? new(SignatureStatus.Valid, name, string.Empty, "RFC 5758 §3.2") : Fail(SignatureStatus.Invalid, "The ECDSA signature does not verify.", "RFC 5758 §3.2");
            }

            switch (alg.Oid)
            {
                case KnownOids.RsaPss:
                    return VerifyPss(key, alg, data, signature, name);
                case KnownOids.Ed25519 or KnownOids.Ed448:
                    if (key.KeyAlgorithm != (alg.Oid == KnownOids.Ed25519 ? KeyAlgorithm.Ed25519 : KeyAlgorithm.Ed448))
                    {
                        return Fail(SignatureStatus.KeyMismatch, $"{name} needs an {name} key; the key is {key.Algorithm.Name}.", "RFC 8410 §3");
                    }

                    bool? edOk = EdwardsDispatch.Verify(alg.Oid, key.KeyBits.Span, data, signature);
                    return edOk switch
                    {
                        true => new(SignatureStatus.Valid, name, string.Empty, "RFC 8032"),
                        false => Fail(SignatureStatus.Invalid, $"The {name} signature does not verify.", "RFC 8032 §5"),
                        _ => Fail(SignatureStatus.AlgorithmNotSupported, $"{name} is not available in this build on {RuntimeInformation.OSDescription}.", "RFC 8410"),
                    };
                case var o when IsComposite(o):
                    return Fail(SignatureStatus.AlgorithmNotSupported, "Composite ML-DSA is a preview and is not verified on this platform.", "draft-ietf-lamps-pq-composite-sigs");
                case var o when o is KnownOids.MlDsa44 or KnownOids.MlDsa65 or KnownOids.MlDsa87:
                    return PostQuantum.VerifyMlDsa(key, alg, data, signature, name);
                case var o when AlgorithmNames.SlhDsaName(o) is not null:
                    return PostQuantum.VerifySlhDsa(key, alg, data, signature, name);
                default:
                    return Fail(SignatureStatus.AlgorithmNotSupported, $"The signature algorithm {alg.Oid} is not known.", "RFC 5280 §4.1.1.2");
            }
        }
        catch (Asn1ParseException e)
        {
            return Fail(SignatureStatus.Malformed, "Parameters or key could not be decoded: " + e.Message, "RFC 5280 §4.1.1.2");
        }
        catch (X509ParseException e)
        {
            return Fail(SignatureStatus.Malformed, e.Message, "RFC 5280 §4.1.1.2");
        }
        catch (NotSupportedException e)
        {
            // PlatformNotSupportedException included: the platform lacks the curve or parameter set.
            return Fail(SignatureStatus.AlgorithmNotSupported, $"{RuntimeInformation.OSDescription} cannot use this key or parameter set: {e.Message}", "RFC 5280 §4.1.1.2");
        }
        catch (CryptographicException e)
        {
            // The platform refuses the key or the encoding (a malformed ECDSA signature, an unsupported curve, a bad modulus).
            return Fail(SignatureStatus.Invalid, "The platform could not check the signature: " + e.Message, "RFC 5280 §4.1.1.3");
        }
        catch (ArgumentException e)
        {
            return Fail(SignatureStatus.Malformed, e.Message, "RFC 5280 §4.1.1.3");
        }
    }

    private static EcCurve? EcCurveOf(string? oid) => oid switch
    {
        KnownOids.P256 => EcCurve.NistP256,
        KnownOids.P384 => EcCurve.NistP384,
        KnownOids.P521 => EcCurve.NistP521,
        KnownOids.BrainpoolP256r1 => EcCurve.BrainpoolP256r1,
        KnownOids.BrainpoolP384r1 => EcCurve.BrainpoolP384r1,
        KnownOids.BrainpoolP512r1 => EcCurve.BrainpoolP512r1,
        _ => null,
    };

    private static bool IsStrictEcdsaSignature(ReadOnlySpan<byte> signature)
    {
        var r = new Asn1Reader(signature, Asn1Rules.Der);
        if (!r.TryReadSequence(out Asn1Reader seq) || r.HasData)
        {
            return false;
        }

        return seq.TryReadUnsignedIntegerBytes(out _) && seq.TryReadUnsignedIntegerBytes(out _) && !seq.HasData;
    }

    private static SignatureVerification VerifyRsa(PublicKeyInfo key, SignatureScheme scheme, RSASignaturePadding padding, ReadOnlySpan<byte> data, ReadOnlySpan<byte> sig, string name)
    {
        if (!Supported(scheme.Hash))
        {
            return new(SignatureStatus.AlgorithmNotSupported, name, $"{scheme.Hash.Name} is not available on {RuntimeInformation.OSDescription}.", "RFC 8017 §8.2");
        }

        if (Platform.RsaVerify != Provider.Bcl)
        {
            // No platform RSA (the browser): the verify-only managed fallback; the public key is an RSAPublicKey (RFC 8017 A.1.1).
            byte[]? digest = PlatformHash.Digest(scheme.Hash, data);
            var r = new Asn1Reader(key.KeyBits.Span, Asn1Rules.Ber);
            Asn1Reader seq = r.ReadSequence();
            ReadOnlySpan<byte> n = seq.ReadUnsignedIntegerBytes();
            ReadOnlySpan<byte> e = seq.ReadUnsignedIntegerBytes();
            bool fb = digest is not null && (padding == RSASignaturePadding.Pss
                ? PlatformSignatures.RsaVerifyPss(n, e, scheme.Hash, scheme.Hash, digest.Length, digest, sig)
                : PlatformSignatures.RsaVerifyPkcs1(n, e, scheme.Hash, digest, sig));
            return fb
                ? new(SignatureStatus.Valid, name, string.Empty, "RFC 8017 §8.2.2")
                : new(SignatureStatus.Invalid, name, "The RSA signature does not verify.", "RFC 8017 §8.2.2");
        }

        using RSA rsa = key.ToRsa();
        bool ok = rsa.VerifyData(data, sig, scheme.Hash, padding);
        return ok
            ? new(SignatureStatus.Valid, name, string.Empty, "RFC 8017 §8.2.2")
            : new(SignatureStatus.Invalid, name, "The RSA signature does not verify.", "RFC 8017 §8.2.2");
    }

    private static SignatureVerification VerifyPss(PublicKeyInfo key, AlgorithmIdentifier alg, ReadOnlySpan<byte> data, ReadOnlySpan<byte> sig, string name)
    {
        if (key.KeyAlgorithm is not (KeyAlgorithm.Rsa or KeyAlgorithm.RsaPss))
        {
            return new(SignatureStatus.KeyMismatch, name, $"RSASSA-PSS needs an RSA key; the key is {key.Algorithm.Name}.", "RFC 4055 §1.2");
        }

        PssParameters p = PssParameters.Parse(alg.Parameters);
        if (p.TrailerField != 1 || p.HashOid != p.MgfHashOid || !TryHash(p.HashOid, out HashAlgorithmName hash))
        {
            return new(SignatureStatus.AlgorithmNotSupported, name, "RSASSA-PSS needs a trailer of 1, MGF1 on the signature hash, and a hash the library knows.", "RFC 4055 §3.1");
        }

        // A key that carries PSS parameters pins the hash and a minimum salt (RFC 4055 §1.2).
        if (key.KeyAlgorithm == KeyAlgorithm.RsaPss && !key.Algorithm.Parameters.IsEmpty)
        {
            PssParameters kp = PssParameters.Parse(key.Algorithm.Parameters);
            if (kp.HashOid != p.HashOid || kp.MgfHashOid != p.MgfHashOid || p.SaltLength < kp.SaltLength)
            {
                return new(SignatureStatus.KeyMismatch, name, "The signature parameters differ from those the RSASSA-PSS key restricts it to.", "RFC 4055 §1.2");
            }
        }

        int digest = hash.Name switch { "SHA1" => 20, "SHA256" or "SHA3-256" => 32, "SHA384" or "SHA3-384" => 48, _ => 64 };
        if (p.SaltLength != digest)
        {
            // The platform's PSS check uses a salt as long as the digest only.
            return new(SignatureStatus.AlgorithmNotSupported, name, $"RSASSA-PSS with a {p.SaltLength}-octet salt on a {digest}-octet hash is not available on {RuntimeInformation.OSDescription}.", "RFC 4055 §3.1");
        }

        return VerifyRsa(key, new SignatureScheme("pss", hash, p.HashOid, p), RSASignaturePadding.Pss, data, sig, name);
    }
}

/// <summary>Ed25519 and Ed448 verification entry point.</summary>
internal static class EdwardsDispatch
{
    /// <summary>Checks an EdDSA signature (RFC 8032, empty context for Ed448 per RFC 8410 §3); the caller passes only Ed25519 or Ed448 identifiers.</summary>
    public static bool? Verify(string algorithmOid, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature) =>
        algorithmOid == KnownOids.Ed25519
            ? publicKey.Length == 32 && signature.Length == 64 && RecursiveAI.OneCrypto.Primitives.Ed25519.Verify(publicKey, message, signature)
            : publicKey.Length == 57 && signature.Length == 114 && RecursiveAI.OneCrypto.Primitives.Ed448.Verify(publicKey, message, default, signature);
}
