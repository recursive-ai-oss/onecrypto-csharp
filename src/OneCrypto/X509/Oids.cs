namespace RecursiveAI.OneCrypto;

/// <summary>Object identifiers of the algorithms, name attributes, extensions and access methods the PKI models know. Dotted strings, so they can be compared and used in switches.</summary>
public static class KnownOids
{
    // Public-key and signature algorithms. RFC 8017 Appendix C, RFC 5480, RFC 8410, RFC 9881 (ML-DSA), RFC 9814 (SLH-DSA), RFC 9935 (ML-KEM).
    /// <summary>rsaEncryption.</summary>
    public const string RsaEncryption = "1.2.840.113549.1.1.1";
    /// <summary>sha1WithRSAEncryption.</summary>
    public const string Sha1WithRsa = "1.2.840.113549.1.1.5";
    /// <summary>sha256WithRSAEncryption.</summary>
    public const string Sha256WithRsa = "1.2.840.113549.1.1.11";
    /// <summary>sha384WithRSAEncryption.</summary>
    public const string Sha384WithRsa = "1.2.840.113549.1.1.12";
    /// <summary>sha512WithRSAEncryption.</summary>
    public const string Sha512WithRsa = "1.2.840.113549.1.1.13";
    /// <summary>sha224WithRSAEncryption.</summary>
    public const string Sha224WithRsa = "1.2.840.113549.1.1.14";
    /// <summary>md5WithRSAEncryption (read only; never accepted by verification).</summary>
    public const string Md5WithRsa = "1.2.840.113549.1.1.4";
    /// <summary>id-RSASSA-PSS.</summary>
    public const string RsaPss = "1.2.840.113549.1.1.10";
    /// <summary>id-RSAES-OAEP.</summary>
    public const string RsaOaep = "1.2.840.113549.1.1.7";
    /// <summary>id-mgf1.</summary>
    public const string Mgf1 = "1.2.840.113549.1.1.8";
    /// <summary>id-ecPublicKey.</summary>
    public const string EcPublicKey = "1.2.840.10045.2.1";
    /// <summary>ecdsa-with-SHA1.</summary>
    public const string EcdsaSha1 = "1.2.840.10045.4.1";
    /// <summary>ecdsa-with-SHA224.</summary>
    public const string EcdsaSha224 = "1.2.840.10045.4.3.1";
    /// <summary>ecdsa-with-SHA256.</summary>
    public const string EcdsaSha256 = "1.2.840.10045.4.3.2";
    /// <summary>ecdsa-with-SHA384.</summary>
    public const string EcdsaSha384 = "1.2.840.10045.4.3.3";
    /// <summary>ecdsa-with-SHA512.</summary>
    public const string EcdsaSha512 = "1.2.840.10045.4.3.4";
    /// <summary>id-ecdsa-with-sha3-256.</summary>
    public const string EcdsaSha3256 = "2.16.840.1.101.3.4.3.10";
    /// <summary>id-ecdsa-with-sha3-384.</summary>
    public const string EcdsaSha3384 = "2.16.840.1.101.3.4.3.11";
    /// <summary>id-ecdsa-with-sha3-512.</summary>
    public const string EcdsaSha3512 = "2.16.840.1.101.3.4.3.12";
    /// <summary>id-rsassa-pkcs1-v1_5-with-sha3-256.</summary>
    public const string RsaSha3256 = "2.16.840.1.101.3.4.3.14";
    /// <summary>id-rsassa-pkcs1-v1_5-with-sha3-384.</summary>
    public const string RsaSha3384 = "2.16.840.1.101.3.4.3.15";
    /// <summary>id-rsassa-pkcs1-v1_5-with-sha3-512.</summary>
    public const string RsaSha3512 = "2.16.840.1.101.3.4.3.16";
    /// <summary>id-Ed25519 (RFC 8410).</summary>
    public const string Ed25519 = "1.3.101.112";
    /// <summary>id-Ed448 (RFC 8410).</summary>
    public const string Ed448 = "1.3.101.113";
    /// <summary>id-X25519 (RFC 8410).</summary>
    public const string X25519 = "1.3.101.110";
    /// <summary>id-X448 (RFC 8410).</summary>
    public const string X448 = "1.3.101.111";
    /// <summary>id-ml-dsa-44.</summary>
    public const string MlDsa44 = "2.16.840.1.101.3.4.3.17";
    /// <summary>id-ml-dsa-65.</summary>
    public const string MlDsa65 = "2.16.840.1.101.3.4.3.18";
    /// <summary>id-ml-dsa-87.</summary>
    public const string MlDsa87 = "2.16.840.1.101.3.4.3.19";
    /// <summary>id-alg-ml-kem-512.</summary>
    public const string MlKem512 = "2.16.840.1.101.3.4.4.1";
    /// <summary>id-alg-ml-kem-768.</summary>
    public const string MlKem768 = "2.16.840.1.101.3.4.4.2";
    /// <summary>id-alg-ml-kem-1024.</summary>
    public const string MlKem1024 = "2.16.840.1.101.3.4.4.3";

    // Curves (RFC 5480, RFC 5639).
    /// <summary>secp256r1 / prime256v1 / P-256.</summary>
    public const string P256 = "1.2.840.10045.3.1.7";
    /// <summary>secp384r1 / P-384.</summary>
    public const string P384 = "1.3.132.0.34";
    /// <summary>secp521r1 / P-521.</summary>
    public const string P521 = "1.3.132.0.35";
    /// <summary>brainpoolP256r1.</summary>
    public const string BrainpoolP256r1 = "1.3.36.3.3.2.8.1.1.7";
    /// <summary>brainpoolP384r1.</summary>
    public const string BrainpoolP384r1 = "1.3.36.3.3.2.8.1.1.11";
    /// <summary>brainpoolP512r1.</summary>
    public const string BrainpoolP512r1 = "1.3.36.3.3.2.8.1.1.13";

    // Hash functions.
    /// <summary>id-sha1.</summary>
    public const string Sha1 = "1.3.14.3.2.26";
    /// <summary>id-sha224.</summary>
    public const string Sha224 = "2.16.840.1.101.3.4.2.4";
    /// <summary>id-sha256.</summary>
    public const string Sha256 = "2.16.840.1.101.3.4.2.1";
    /// <summary>id-sha384.</summary>
    public const string Sha384 = "2.16.840.1.101.3.4.2.2";
    /// <summary>id-sha512.</summary>
    public const string Sha512 = "2.16.840.1.101.3.4.2.3";
    /// <summary>id-sha3-256.</summary>
    public const string Sha3256 = "2.16.840.1.101.3.4.2.8";
    /// <summary>id-sha3-384.</summary>
    public const string Sha3384 = "2.16.840.1.101.3.4.2.9";
    /// <summary>id-sha3-512.</summary>
    public const string Sha3512 = "2.16.840.1.101.3.4.2.10";

    // Name attributes (RFC 5280 Appendix A.1, X.520).
    /// <summary>commonName.</summary>
    public const string CommonName = "2.5.4.3";
    /// <summary>countryName.</summary>
    public const string Country = "2.5.4.6";
    /// <summary>localityName.</summary>
    public const string Locality = "2.5.4.7";
    /// <summary>stateOrProvinceName.</summary>
    public const string State = "2.5.4.8";
    /// <summary>organizationName.</summary>
    public const string Organization = "2.5.4.10";
    /// <summary>organizationalUnitName.</summary>
    public const string OrganizationalUnit = "2.5.4.11";
    /// <summary>serialNumber.</summary>
    public const string SerialNumber = "2.5.4.5";
    /// <summary>emailAddress (PKCS #9).</summary>
    public const string EmailAddress = "1.2.840.113549.1.9.1";
    /// <summary>domainComponent.</summary>
    public const string DomainComponent = "0.9.2342.19200300.100.1.25";

    // Extensions (RFC 5280 §4.2.1, §5.2, RFC 6960).
    /// <summary>subjectKeyIdentifier.</summary>
    public const string SubjectKeyIdentifier = "2.5.29.14";
    /// <summary>keyUsage.</summary>
    public const string KeyUsage = "2.5.29.15";
    /// <summary>subjectAltName.</summary>
    public const string SubjectAltName = "2.5.29.17";
    /// <summary>issuerAltName.</summary>
    public const string IssuerAltName = "2.5.29.18";
    /// <summary>basicConstraints.</summary>
    public const string BasicConstraints = "2.5.29.19";
    /// <summary>cRLNumber.</summary>
    public const string CrlNumber = "2.5.29.20";
    /// <summary>cRLReasons.</summary>
    public const string CrlReason = "2.5.29.21";
    /// <summary>invalidityDate.</summary>
    public const string InvalidityDate = "2.5.29.24";
    /// <summary>deltaCRLIndicator.</summary>
    public const string DeltaCrlIndicator = "2.5.29.27";
    /// <summary>issuingDistributionPoint.</summary>
    public const string IssuingDistributionPoint = "2.5.29.28";
    /// <summary>certificateIssuer.</summary>
    public const string CertificateIssuer = "2.5.29.29";
    /// <summary>nameConstraints.</summary>
    public const string NameConstraints = "2.5.29.30";
    /// <summary>cRLDistributionPoints.</summary>
    public const string CrlDistributionPoints = "2.5.29.31";
    /// <summary>certificatePolicies.</summary>
    public const string CertificatePolicies = "2.5.29.32";
    /// <summary>policyMappings.</summary>
    public const string PolicyMappings = "2.5.29.33";
    /// <summary>authorityKeyIdentifier.</summary>
    public const string AuthorityKeyIdentifier = "2.5.29.35";
    /// <summary>policyConstraints.</summary>
    public const string PolicyConstraints = "2.5.29.36";
    /// <summary>extKeyUsage.</summary>
    public const string ExtendedKeyUsage = "2.5.29.37";
    /// <summary>freshestCRL.</summary>
    public const string FreshestCrl = "2.5.29.46";
    /// <summary>inhibitAnyPolicy.</summary>
    public const string InhibitAnyPolicy = "2.5.29.54";
    /// <summary>authorityInfoAccess.</summary>
    public const string AuthorityInfoAccess = "1.3.6.1.5.5.7.1.1";
    /// <summary>subjectInfoAccess.</summary>
    public const string SubjectInfoAccess = "1.3.6.1.5.5.7.1.11";
    /// <summary>id-pkix-ocsp-nonce.</summary>
    public const string OcspNonce = "1.3.6.1.5.5.7.48.1.2";
    /// <summary>id-pkix-ocsp-nocheck.</summary>
    public const string OcspNoCheck = "1.3.6.1.5.5.7.48.1.5";
    /// <summary>id-pkix-ocsp-basic.</summary>
    public const string OcspBasic = "1.3.6.1.5.5.7.48.1.1";
    /// <summary>id-ad-ocsp (access method).</summary>
    public const string AdOcsp = "1.3.6.1.5.5.7.48.1";
    /// <summary>id-ad-caIssuers (access method).</summary>
    public const string AdCaIssuers = "1.3.6.1.5.5.7.48.2";

    // Extended key usages (RFC 5280 §4.2.1.12).
    /// <summary>anyExtendedKeyUsage.</summary>
    public const string AnyExtendedKeyUsage = "2.5.29.37.0";
    /// <summary>id-kp-serverAuth.</summary>
    public const string ServerAuth = "1.3.6.1.5.5.7.3.1";
    /// <summary>id-kp-clientAuth.</summary>
    public const string ClientAuth = "1.3.6.1.5.5.7.3.2";
    /// <summary>id-kp-codeSigning.</summary>
    public const string CodeSigning = "1.3.6.1.5.5.7.3.3";
    /// <summary>id-kp-emailProtection.</summary>
    public const string EmailProtection = "1.3.6.1.5.5.7.3.4";
    /// <summary>id-kp-timeStamping.</summary>
    public const string TimeStamping = "1.3.6.1.5.5.7.3.8";
    /// <summary>id-kp-OCSPSigning.</summary>
    public const string OcspSigning = "1.3.6.1.5.5.7.3.9";

    /// <summary>PKCS #9 extensionRequest attribute of a certification request.</summary>
    public const string ExtensionRequest = "1.2.840.113549.1.9.14";
    /// <summary>anyPolicy.</summary>
    public const string AnyPolicy = "2.5.29.32.0";
}
