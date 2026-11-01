namespace RecursiveAI.OneCrypto.OpenPgp.Packets;

/// <summary>Packet type IDs (RFC 9580 §5, §4.3; LibrePGP for tag 20). Values with no name are kept as received.</summary>
public enum PacketTag : byte
{
    /// <summary>Reserved; a packet with this tag must not be used.</summary>
    Reserved = 0,

    /// <summary>Public Key Encrypted Session Key (§5.1).</summary>
    PublicKeyEncryptedSessionKey = 1,

    /// <summary>Signature (§5.2).</summary>
    Signature = 2,

    /// <summary>Symmetric Key Encrypted Session Key (§5.3).</summary>
    SymmetricKeyEncryptedSessionKey = 3,

    /// <summary>One-Pass Signature (§5.4).</summary>
    OnePassSignature = 4,

    /// <summary>Secret Key (§5.5.1.3).</summary>
    SecretKey = 5,

    /// <summary>Public Key (§5.5.1.1).</summary>
    PublicKey = 6,

    /// <summary>Secret Subkey (§5.5.1.4).</summary>
    SecretSubkey = 7,

    /// <summary>Compressed Data (§5.6).</summary>
    CompressedData = 8,

    /// <summary>Symmetrically Encrypted Data, obsolete and unauthenticated (§5.7).</summary>
    SymmetricallyEncryptedData = 9,

    /// <summary>Marker (§5.8).</summary>
    Marker = 10,

    /// <summary>Literal Data (§5.9).</summary>
    LiteralData = 11,

    /// <summary>Trust (§5.10), local to an implementation.</summary>
    Trust = 12,

    /// <summary>User ID (§5.11).</summary>
    UserId = 13,

    /// <summary>Public Subkey (§5.5.1.2).</summary>
    PublicSubkey = 14,

    /// <summary>User Attribute (§5.12).</summary>
    UserAttribute = 17,

    /// <summary>Symmetrically Encrypted and Integrity Protected Data, versions 1 and 2 (§5.13).</summary>
    SymmetricallyEncryptedIntegrityProtectedData = 18,

    /// <summary>Modification Detection Code (version 1 SEIPD only; deprecated as a packet by RFC 9580 §5.14).</summary>
    ModificationDetectionCode = 19,

    /// <summary>OCB Encrypted Data (LibrePGP §5.16).</summary>
    OcbEncryptedData = 20,

    /// <summary>Padding (§5.14).</summary>
    Padding = 21,
}

/// <summary>How a packet header is encoded (RFC 9580 §4.2).</summary>
public enum PacketHeaderFormat : byte
{
    /// <summary>The legacy format (§4.2.2): tags 0 to 15, length in 0, 1, 2 or 4 octets or "until the end".</summary>
    Old = 0,

    /// <summary>The OpenPGP format (§4.2.1): tags 0 to 63, one-, two- or five-octet lengths, or partial lengths.</summary>
    New = 1,
}

/// <summary>How the length of a packet body is encoded (RFC 9580 §4.2).</summary>
public enum PacketLengthKind : byte
{
    /// <summary>A definite length in the old format, one octet.</summary>
    OldOneOctet = 0,

    /// <summary>A definite length in the old format, two octets.</summary>
    OldTwoOctet = 1,

    /// <summary>A definite length in the old format, four octets.</summary>
    OldFourOctet = 2,

    /// <summary>Old format "indeterminate length": the body runs to the end of the input (§4.2.2.4).</summary>
    OldIndeterminate = 3,

    /// <summary>New format, one-octet length (0 to 191).</summary>
    NewOneOctet = 4,

    /// <summary>New format, two-octet length (192 to 8,383).</summary>
    NewTwoOctet = 5,

    /// <summary>New format, five-octet length (0xFF then four octets).</summary>
    NewFiveOctet = 6,

    /// <summary>New format partial body lengths: one or more partial chunks then a final definite length (§4.2.1.4).</summary>
    NewPartial = 7,
}

/// <summary>Public-key algorithm IDs (RFC 9580 §9.1, RFC 9980 §2.1, LibrePGP §9.1).</summary>
public enum PublicKeyAlgorithm : byte
{
    /// <summary>No algorithm.</summary>
    None = 0,

    /// <summary>RSA, encrypt or sign.</summary>
    Rsa = 1,

    /// <summary>RSA, encrypt only (deprecated).</summary>
    RsaEncryptOnly = 2,

    /// <summary>RSA, sign only (deprecated).</summary>
    RsaSignOnly = 3,

    /// <summary>Kyber with an ECDH component, as GnuPG writes it (LibrePGP §5.6.7).</summary>
    LibrePgpKyber = 8,

    /// <summary>Elgamal, encrypt only.</summary>
    ElGamal = 16,

    /// <summary>DSA.</summary>
    Dsa = 17,

    /// <summary>ECDH.</summary>
    Ecdh = 18,

    /// <summary>ECDSA.</summary>
    Ecdsa = 19,

    /// <summary>EdDSA in the legacy MPI-point encoding, with an OID (RFC 9580 §5.5.5.5).</summary>
    EdDsaLegacy = 22,

    /// <summary>X25519 (RFC 9580 §5.5.5.7).</summary>
    X25519 = 25,

    /// <summary>X448 (RFC 9580 §5.5.5.8).</summary>
    X448 = 26,

    /// <summary>Ed25519 (RFC 9580 §5.5.5.9).</summary>
    Ed25519 = 27,

    /// <summary>Ed448 (RFC 9580 §5.5.5.10).</summary>
    Ed448 = 28,

    /// <summary>ML-DSA-65 with Ed25519 (RFC 9980).</summary>
    MlDsa65Ed25519 = 30,

    /// <summary>ML-DSA-87 with Ed448 (RFC 9980).</summary>
    MlDsa87Ed448 = 31,

    /// <summary>SLH-DSA-SHAKE-128s (RFC 9980).</summary>
    SlhDsaShake128s = 32,

    /// <summary>SLH-DSA-SHAKE-128f (RFC 9980).</summary>
    SlhDsaShake128f = 33,

    /// <summary>SLH-DSA-SHAKE-256s (RFC 9980).</summary>
    SlhDsaShake256s = 34,

    /// <summary>ML-KEM-768 with X25519 (RFC 9980).</summary>
    MlKem768X25519 = 35,

    /// <summary>ML-KEM-1024 with X448 (RFC 9980).</summary>
    MlKem1024X448 = 36,
}

/// <summary>Symmetric-key algorithm IDs (RFC 9580 §9.3).</summary>
public enum SymmetricAlgorithm : byte
{
    /// <summary>Plaintext or unencrypted.</summary>
    Plaintext = 0,

    /// <summary>IDEA (legacy).</summary>
    Idea = 1,

    /// <summary>TripleDES (legacy).</summary>
    TripleDes = 2,

    /// <summary>CAST5 (legacy).</summary>
    Cast5 = 3,

    /// <summary>Blowfish (legacy).</summary>
    Blowfish = 4,

    /// <summary>AES with a 128-bit key.</summary>
    Aes128 = 7,

    /// <summary>AES with a 192-bit key.</summary>
    Aes192 = 8,

    /// <summary>AES with a 256-bit key.</summary>
    Aes256 = 9,

    /// <summary>Twofish with a 256-bit key.</summary>
    Twofish = 10,

    /// <summary>Camellia with a 128-bit key.</summary>
    Camellia128 = 11,

    /// <summary>Camellia with a 192-bit key.</summary>
    Camellia192 = 12,

    /// <summary>Camellia with a 256-bit key.</summary>
    Camellia256 = 13,
}

/// <summary>AEAD algorithm IDs (RFC 9580 §9.6; LibrePGP's mode octet uses the same values for EAX and OCB).</summary>
public enum AeadAlgorithm : byte
{
    /// <summary>EAX (LibrePGP only; RFC 9580 reserves 1).</summary>
    Eax = 1,

    /// <summary>OCB.</summary>
    Ocb = 2,

    /// <summary>GCM.</summary>
    Gcm = 3,
}

/// <summary>Hash algorithm IDs (RFC 9580 §9.5).</summary>
public enum PgpHashAlgorithm : byte
{
    /// <summary>No hash.</summary>
    None = 0,

    /// <summary>MD5 (legacy).</summary>
    Md5 = 1,

    /// <summary>SHA-1.</summary>
    Sha1 = 2,

    /// <summary>RIPEMD-160.</summary>
    Ripemd160 = 3,

    /// <summary>SHA-256.</summary>
    Sha256 = 8,

    /// <summary>SHA-384.</summary>
    Sha384 = 9,

    /// <summary>SHA-512.</summary>
    Sha512 = 10,

    /// <summary>SHA-224.</summary>
    Sha224 = 11,

    /// <summary>SHA3-256.</summary>
    Sha3256 = 12,

    /// <summary>SHA3-512.</summary>
    Sha3512 = 14,
}

/// <summary>Compression algorithm IDs (RFC 9580 §9.4).</summary>
public enum CompressionAlgorithm : byte
{
    /// <summary>Uncompressed.</summary>
    Uncompressed = 0,

    /// <summary>ZIP (raw DEFLATE, RFC 1951).</summary>
    Zip = 1,

    /// <summary>ZLIB (RFC 1950).</summary>
    Zlib = 2,

    /// <summary>BZip2.</summary>
    BZip2 = 3,
}

/// <summary>Signature types (RFC 9580 §5.2.1).</summary>
public enum SignatureType : byte
{
    /// <summary>Signature of a binary document.</summary>
    Binary = 0x00,

    /// <summary>Signature of a canonical text document.</summary>
    Text = 0x01,

    /// <summary>Standalone signature.</summary>
    Standalone = 0x02,

    /// <summary>Generic certification of a User ID and public key.</summary>
    GenericCertification = 0x10,

    /// <summary>Persona certification.</summary>
    PersonaCertification = 0x11,

    /// <summary>Casual certification.</summary>
    CasualCertification = 0x12,

    /// <summary>Positive certification.</summary>
    PositiveCertification = 0x13,

    /// <summary>Subkey binding signature.</summary>
    SubkeyBinding = 0x18,

    /// <summary>Primary key binding ("back") signature.</summary>
    PrimaryKeyBinding = 0x19,

    /// <summary>Direct key signature.</summary>
    DirectKey = 0x1F,

    /// <summary>Key revocation.</summary>
    KeyRevocation = 0x20,

    /// <summary>Subkey revocation.</summary>
    SubkeyRevocation = 0x28,

    /// <summary>Certification revocation.</summary>
    CertificationRevocation = 0x30,

    /// <summary>Timestamp signature.</summary>
    Timestamp = 0x40,

    /// <summary>Third-party confirmation signature.</summary>
    ThirdPartyConfirmation = 0x50,
}

/// <summary>Signature subpacket type IDs (RFC 9580 §5.2.3.7, LibrePGP §5.2.3.2). The critical bit is not part of the type.</summary>
public enum SubpacketType : byte
{
    /// <summary>Signature Creation Time.</summary>
    SignatureCreationTime = 2,

    /// <summary>Signature Expiration Time.</summary>
    SignatureExpirationTime = 3,

    /// <summary>Exportable Certification.</summary>
    ExportableCertification = 4,

    /// <summary>Trust Signature.</summary>
    TrustSignature = 5,

    /// <summary>Regular Expression.</summary>
    RegularExpression = 6,

    /// <summary>Revocable.</summary>
    Revocable = 7,

    /// <summary>Key Expiration Time.</summary>
    KeyExpirationTime = 9,

    /// <summary>Preferred Symmetric Ciphers for v1 SEIPD.</summary>
    PreferredSymmetricAlgorithms = 11,

    /// <summary>Revocation Key (deprecated).</summary>
    RevocationKey = 12,

    /// <summary>Issuer Key ID.</summary>
    IssuerKeyId = 16,

    /// <summary>Notation Data.</summary>
    NotationData = 20,

    /// <summary>Preferred Hash Algorithms.</summary>
    PreferredHashAlgorithms = 21,

    /// <summary>Preferred Compression Algorithms.</summary>
    PreferredCompressionAlgorithms = 22,

    /// <summary>Key Server Preferences.</summary>
    KeyServerPreferences = 23,

    /// <summary>Preferred Key Server.</summary>
    PreferredKeyServer = 24,

    /// <summary>Primary User ID.</summary>
    PrimaryUserId = 25,

    /// <summary>Policy URI.</summary>
    PolicyUri = 26,

    /// <summary>Key Flags.</summary>
    KeyFlags = 27,

    /// <summary>Signer's User ID.</summary>
    SignersUserId = 28,

    /// <summary>Reason for Revocation.</summary>
    ReasonForRevocation = 29,

    /// <summary>Features.</summary>
    Features = 30,

    /// <summary>Signature Target.</summary>
    SignatureTarget = 31,

    /// <summary>Embedded Signature.</summary>
    EmbeddedSignature = 32,

    /// <summary>Issuer Fingerprint.</summary>
    IssuerFingerprint = 33,

    /// <summary>Preferred AEAD Algorithms (the pre-RFC 9580 form, reserved now).</summary>
    PreferredAeadAlgorithms = 34,

    /// <summary>Intended Recipient Fingerprint.</summary>
    IntendedRecipientFingerprint = 35,

    /// <summary>Attested Certifications (reserved by RFC 9580, used by existing implementations).</summary>
    AttestedCertifications = 37,

    /// <summary>Key Block (reserved).</summary>
    KeyBlock = 38,

    /// <summary>Preferred AEAD Ciphersuites.</summary>
    PreferredAeadCiphersuites = 39,
}

/// <summary>String-to-key specifier types (RFC 9580 §3.7.1).</summary>
public enum S2kType : byte
{
    /// <summary>Simple S2K (legacy).</summary>
    Simple = 0,

    /// <summary>Salted S2K.</summary>
    Salted = 1,

    /// <summary>Iterated and salted S2K.</summary>
    IteratedSalted = 3,

    /// <summary>Argon2 (RFC 9106).</summary>
    Argon2 = 4,

    /// <summary>GnuPG's private-use "GNU" extension, 101 (the secret key is absent or on a card).</summary>
    GnuExtension = 101,
}
