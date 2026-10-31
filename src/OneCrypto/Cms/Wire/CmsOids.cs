namespace RecursiveAI.OneCrypto.Wire.Cms;

/// <summary>Object identifiers of the CMS content types, attributes and algorithms (RFC 5652, 5083, 3274, 5035, 5753, 8418, 3211, 9629 and the algorithm profiles around them).</summary>
public static class CmsOids
{
    // Content types: RFC 5652 §4 and §14, RFC 5083 §2.1, RFC 3274 §1.1, RFC 3161 §2.4.2.
    /// <summary>id-data.</summary>
    public const string Data = "1.2.840.113549.1.7.1";
    /// <summary>id-signedData.</summary>
    public const string SignedData = "1.2.840.113549.1.7.2";
    /// <summary>id-envelopedData.</summary>
    public const string EnvelopedData = "1.2.840.113549.1.7.3";
    /// <summary>id-digestedData.</summary>
    public const string DigestedData = "1.2.840.113549.1.7.5";
    /// <summary>id-encryptedData.</summary>
    public const string EncryptedData = "1.2.840.113549.1.7.6";
    /// <summary>id-ct-authData (AuthenticatedData).</summary>
    public const string AuthenticatedData = "1.2.840.113549.1.9.16.1.2";
    /// <summary>id-ct-TSTInfo.</summary>
    public const string TstInfo = "1.2.840.113549.1.9.16.1.4";
    /// <summary>id-ct-compressedData.</summary>
    public const string CompressedData = "1.2.840.113549.1.9.16.1.9";
    /// <summary>id-ct-authEnvelopedData.</summary>
    public const string AuthEnvelopedData = "1.2.840.113549.1.9.16.1.23";

    // Attributes: RFC 5652 §11, RFC 2634 §5.4, RFC 5035 §3, RFC 6211 §2.
    /// <summary>id-contentType.</summary>
    public const string ContentType = "1.2.840.113549.1.9.3";
    /// <summary>id-messageDigest.</summary>
    public const string MessageDigest = "1.2.840.113549.1.9.4";
    /// <summary>id-signingTime.</summary>
    public const string SigningTime = "1.2.840.113549.1.9.5";
    /// <summary>id-countersignature.</summary>
    public const string Countersignature = "1.2.840.113549.1.9.6";
    /// <summary>id-aa-signingCertificate (ESS, SHA-1 certificate hashes).</summary>
    public const string SigningCertificate = "1.2.840.113549.1.9.16.2.12";
    /// <summary>id-aa-signingCertificateV2.</summary>
    public const string SigningCertificateV2 = "1.2.840.113549.1.9.16.2.47";
    /// <summary>id-aa-signatureTimeStampToken.</summary>
    public const string SignatureTimeStampToken = "1.2.840.113549.1.9.16.2.14";
    /// <summary>id-aa-CMSAlgorithmProtection.</summary>
    public const string CmsAlgorithmProtection = "1.2.840.113549.1.9.52";

    // Recipient info: RFC 5652 §6, RFC 9629 §3.
    /// <summary>id-ori-kem (the OtherRecipientInfo type of KEMRecipientInfo).</summary>
    public const string OriKem = "1.2.840.113549.1.9.16.13.3";
    /// <summary>id-alg-PWRI-KEK (RFC 3211 §3).</summary>
    public const string PwriKek = "1.2.840.113549.1.9.16.3.9";
    /// <summary>id-PBKDF2 (RFC 8018).</summary>
    public const string Pbkdf2 = "1.2.840.113549.1.5.12";
    /// <summary>id-alg-zlibCompress.</summary>
    public const string ZlibCompress = "1.2.840.113549.1.9.16.3.8";

    // Key agreement: RFC 5753 §7.1, RFC 8418 §2.
    /// <summary>dhSinglePass-stdDH-sha1kdf-scheme.</summary>
    public const string StdDhSha1Kdf = "1.3.133.16.840.63.0.2";
    /// <summary>dhSinglePass-stdDH-sha224kdf-scheme.</summary>
    public const string StdDhSha224Kdf = "1.3.132.1.11.0";
    /// <summary>dhSinglePass-stdDH-sha256kdf-scheme.</summary>
    public const string StdDhSha256Kdf = "1.3.132.1.11.1";
    /// <summary>dhSinglePass-stdDH-sha384kdf-scheme.</summary>
    public const string StdDhSha384Kdf = "1.3.132.1.11.2";
    /// <summary>dhSinglePass-stdDH-sha512kdf-scheme.</summary>
    public const string StdDhSha512Kdf = "1.3.132.1.11.3";
    /// <summary>dhSinglePass-stdDH-hkdf-sha256-scheme.</summary>
    public const string StdDhHkdfSha256 = "1.2.840.113549.1.9.16.3.19";
    /// <summary>dhSinglePass-stdDH-hkdf-sha384-scheme.</summary>
    public const string StdDhHkdfSha384 = "1.2.840.113549.1.9.16.3.20";
    /// <summary>dhSinglePass-stdDH-hkdf-sha512-scheme.</summary>
    public const string StdDhHkdfSha512 = "1.2.840.113549.1.9.16.3.21";
    /// <summary>id-alg-hkdf-with-sha256 (RFC 8619).</summary>
    public const string HkdfSha256 = "1.2.840.113549.1.9.16.3.28";
    /// <summary>id-alg-hkdf-with-sha384.</summary>
    public const string HkdfSha384 = "1.2.840.113549.1.9.16.3.29";
    /// <summary>id-alg-hkdf-with-sha512.</summary>
    public const string HkdfSha512 = "1.2.840.113549.1.9.16.3.30";

    // Content encryption and key wrap: RFC 3565, RFC 5084, RFC 3370.
    /// <summary>id-aes128-CBC.</summary>
    public const string Aes128Cbc = "2.16.840.1.101.3.4.1.2";
    /// <summary>id-aes192-CBC.</summary>
    public const string Aes192Cbc = "2.16.840.1.101.3.4.1.22";
    /// <summary>id-aes256-CBC.</summary>
    public const string Aes256Cbc = "2.16.840.1.101.3.4.1.42";
    /// <summary>id-aes128-wrap.</summary>
    public const string Aes128Wrap = "2.16.840.1.101.3.4.1.5";
    /// <summary>id-aes192-wrap.</summary>
    public const string Aes192Wrap = "2.16.840.1.101.3.4.1.25";
    /// <summary>id-aes256-wrap.</summary>
    public const string Aes256Wrap = "2.16.840.1.101.3.4.1.45";
    /// <summary>id-aes128-wrap-pad.</summary>
    public const string Aes128WrapPad = "2.16.840.1.101.3.4.1.8";
    /// <summary>id-aes192-wrap-pad.</summary>
    public const string Aes192WrapPad = "2.16.840.1.101.3.4.1.28";
    /// <summary>id-aes256-wrap-pad.</summary>
    public const string Aes256WrapPad = "2.16.840.1.101.3.4.1.48";
    /// <summary>id-aes128-GCM.</summary>
    public const string Aes128Gcm = "2.16.840.1.101.3.4.1.6";
    /// <summary>id-aes192-GCM.</summary>
    public const string Aes192Gcm = "2.16.840.1.101.3.4.1.26";
    /// <summary>id-aes256-GCM.</summary>
    public const string Aes256Gcm = "2.16.840.1.101.3.4.1.46";
    /// <summary>id-aes128-CCM.</summary>
    public const string Aes128Ccm = "2.16.840.1.101.3.4.1.7";
    /// <summary>id-aes192-CCM.</summary>
    public const string Aes192Ccm = "2.16.840.1.101.3.4.1.27";
    /// <summary>id-aes256-CCM.</summary>
    public const string Aes256Ccm = "2.16.840.1.101.3.4.1.47";
    /// <summary>des-ede3-cbc (read only: legacy).</summary>
    public const string TripleDesCbc = "1.2.840.113549.3.7";

    // MACs: RFC 4231, RFC 5753 §7.2.
    /// <summary>hmacWithSHA1.</summary>
    public const string HmacSha1 = "1.3.6.1.5.5.8.1.2";
    /// <summary>id-hmacWithSHA224.</summary>
    public const string HmacSha224 = "1.2.840.113549.2.8";
    /// <summary>id-hmacWithSHA256.</summary>
    public const string HmacSha256 = "1.2.840.113549.2.9";
    /// <summary>id-hmacWithSHA384.</summary>
    public const string HmacSha384 = "1.2.840.113549.2.10";
    /// <summary>id-hmacWithSHA512.</summary>
    public const string HmacSha512 = "1.2.840.113549.2.11";

    /// <summary>id-shake256 (RFC 8419 §3.1: the digest for Ed448).</summary>
    public const string Shake256 = "2.16.840.1.101.3.4.2.12";
}
