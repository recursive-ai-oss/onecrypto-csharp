using System.Security.Cryptography;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Primitives;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>The algorithm sets and key versions <see cref="PgpKeyGenerator"/> can produce. No profile writes a version 5 key.</summary>
public enum PgpKeyProfile
{
    /// <summary>Version 6 Ed25519 primary key and X25519 encryption subkey (RFC 9580). The default.</summary>
    Rfc9580 = 0,

    /// <summary>Version 4 key with the native Ed25519 and X25519 algorithms (RFC 9580 §5.5.5.6, §5.5.5.8).</summary>
    Rfc9580V4,

    /// <summary>Version 6 Ed448 primary key and X448 encryption subkey.</summary>
    Rfc9580Ed448,

    /// <summary>Version 6 RSA-3072 primary key and subkey.</summary>
    Rfc9580Rsa,

    /// <summary>Version 4 EdDSA (legacy, Ed25519 curve) and ECDH (Curve25519) keys, the layout RFC 4880 implementations read.</summary>
    Rfc4880Curve25519,

    /// <summary>Version 4 RSA-3072 primary key and subkey, for readers that predate elliptic curves.</summary>
    Rfc4880Rsa,

    /// <summary>Version 4 ECDSA and ECDH keys on NIST P-256.</summary>
    NistP256,

    /// <summary>Version 4 ECDSA and ECDH keys on NIST P-384.</summary>
    NistP384,

    /// <summary>Version 4 ECDSA and ECDH keys on NIST P-521.</summary>
    NistP521,

    /// <summary>Version 6 ML-DSA-65 + Ed25519 primary key and ML-KEM-768 + X25519 subkey (RFC 9980). Needs a platform with ML-DSA and ML-KEM.</summary>
    Rfc9980Pqc,

    /// <summary>Version 6 ML-DSA-87 + Ed448 primary key and ML-KEM-1024 + X448 subkey (RFC 9980). Needs a platform with ML-DSA and ML-KEM.</summary>
    Rfc9980PqcHigh,
}

/// <summary>Settings for <see cref="PgpKeyGenerator.Generate"/>.</summary>
public sealed class PgpKeyGenerationOptions
{
    /// <summary>The creation time of the key and its self-signatures. Required: there is no default clock.</summary>
    public required DateTimeOffset Now { get; init; }

    /// <summary>User IDs to bind to the key (UTF-8 text, certified as written). The first is the primary User ID. Default none.</summary>
    public IReadOnlyList<string> UserIds { get; init; } = [];

    /// <summary>Which algorithms and key version. Default <see cref="PgpKeyProfile.Rfc9580"/>.</summary>
    public PgpKeyProfile Profile { get; init; } = PgpKeyProfile.Rfc9580;

    /// <summary>True to leave out the encryption subkey, so the key can certify and sign but not decrypt. Default false.</summary>
    public bool SigningOnly { get; init; }

    /// <summary>The password (UTF-8 octets) that protects the secret keys, or null to write them unprotected. Default null.</summary>
    public byte[]? Password { get; init; }

    /// <summary>How long the key stays valid from <see cref="Now"/>; null for no expiry. Default null.</summary>
    public TimeSpan? ValidFor { get; init; }

    /// <summary>The policy for the self-signatures and for the S2K cost written. <see cref="CryptoPolicy.Standard"/> when null.</summary>
    public CryptoPolicy? Policy { get; init; }
}

/// <summary>Generates OpenPGP keys (RFC 9580 §5.5, §10.1; RFC 9980 for the post-quantum composites).</summary>
public static class PgpKeyGenerator
{
    /// <summary>
    /// Generates a certificate with its secret key material: a primary key that may certify and sign, an encryption subkey unless
    /// <see cref="PgpKeyGenerationOptions.SigningOnly"/>, a direct-key signature (always for version 6) and a certification per User ID, all carrying
    /// key flags, expiry, features and algorithm preferences. Only version 4 and 6 keys are written.
    /// </summary>
    /// <exception cref="AlgorithmNotSupportedException">The platform lacks the algorithm (for example ML-DSA or ML-KEM).</exception>
    /// <exception cref="PgpException">The policy refuses the self-signature hash or the key size.</exception>
    public static PgpCertificate Generate(PgpKeyGenerationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        CryptoPolicy policy = options.Policy ?? CryptoPolicy.Standard;
        (KeyKind primaryKind, KeyKind? subKind, byte version) = Plan(options.Profile);
        uint created = PgpTime.ToSeconds(options.Now);
        uint? expiry = options.ValidFor is { } v ? checked((uint)v.TotalSeconds) : null;

        NewKey primary = NewKey.Create(primaryKind, version, created, subkey: false);
        var packets = new List<Packet> { SecretKeyWriter.Build(primary.Public, primary.Secret, [], protect: false) };
        PgpCertificate bare = PgpCertificate.FromTransferable(TransferableKey.Parse(packets));
        using PgpSecretKey ps = PgpSecretKey.Unlock(bare.Primary);
        byte[] pkInput = SignatureEngine.KeyInput(primary.Public);

        PgpKeyUsage primaryUsage = PgpKeyUsage.Certify | PgpKeyUsage.Sign;
        List<SignatureSubpacket> prefs = Preferences(options.Profile);
        var selfHashed = new List<SignatureSubpacket> { Subpackets.KeyFlags(primaryUsage) };
        if (expiry is { } e)
        {
            selfHashed.Add(Subpackets.KeyExpiration(e));
        }

        selfHashed.AddRange(prefs);

        // RFC 9580 §5.2.3.10, §10.1: a version 6 key must have a direct-key signature; for version 4 it carries the key's properties when there is no User ID.
        if (version == 6 || options.UserIds.Count == 0)
        {
            packets.Add(KeySignatures.Make(ps, SignatureType.DirectKey, selfHashed, options.Now, policy, pkInput));
        }

        for (int i = 0; i < options.UserIds.Count; i++)
        {
            Packet uid = Packet.Create((byte)PacketTag.UserId, System.Text.Encoding.UTF8.GetBytes(options.UserIds[i]));
            var hashed = new List<SignatureSubpacket>(selfHashed);
            if (i == 0)
            {
                hashed.Add(Subpackets.PrimaryUserId(true));
            }

            packets.Add(uid);
            packets.Add(KeySignatures.Make(ps, SignatureType.PositiveCertification, hashed, options.Now, policy, pkInput, SignatureEngine.UserIdInput(uid)));
        }

        if (!options.SigningOnly && subKind is { } sk)
        {
            NewKey sub = NewKey.Create(sk, version, created, subkey: true);
            packets.Add(SecretKeyWriter.Build(sub.Public, sub.Secret, [], protect: false));
            var hashed = new List<SignatureSubpacket> { Subpackets.KeyFlags(PgpKeyUsage.EncryptCommunications | PgpKeyUsage.EncryptStorage) };
            if (expiry is { } se)
            {
                hashed.Add(Subpackets.KeyExpiration(se));
            }

            packets.Add(KeySignatures.Make(ps, SignatureType.SubkeyBinding, hashed, options.Now, policy, pkInput, SignatureEngine.KeyInput(sub.Public)));
            CryptographicOperations.ZeroMemory(sub.Secret);
        }

        CryptographicOperations.ZeroMemory(primary.Secret);
        PgpCertificate cert = PgpCertificate.FromTransferable(TransferableKey.Parse(packets));
        return options.Password is { } pw ? PgpKeyEditor.SetPassword(cert, [], pw, policy) : cert;
    }

    internal enum KeyKind
    {
        Ed25519, X25519, Ed448, X448, EdDsaLegacy, EcdhCurve25519, Rsa3072, EcdsaP256, EcdsaP384, EcdsaP521, EcdhP256, EcdhP384, EcdhP521,
        MlDsa65Ed25519, MlDsa87Ed448, MlKem768X25519, MlKem1024X448,
    }

    private static (KeyKind Primary, KeyKind? Sub, byte Version) Plan(PgpKeyProfile profile) => profile switch
    {
        PgpKeyProfile.Rfc9580 => (KeyKind.Ed25519, KeyKind.X25519, 6),
        PgpKeyProfile.Rfc9580V4 => (KeyKind.Ed25519, KeyKind.X25519, 4),
        PgpKeyProfile.Rfc9580Ed448 => (KeyKind.Ed448, KeyKind.X448, 6),
        PgpKeyProfile.Rfc9580Rsa => (KeyKind.Rsa3072, KeyKind.Rsa3072, 6),
        PgpKeyProfile.Rfc4880Curve25519 => (KeyKind.EdDsaLegacy, KeyKind.EcdhCurve25519, 4),
        PgpKeyProfile.Rfc4880Rsa => (KeyKind.Rsa3072, KeyKind.Rsa3072, 4),
        PgpKeyProfile.NistP256 => (KeyKind.EcdsaP256, KeyKind.EcdhP256, 4),
        PgpKeyProfile.NistP384 => (KeyKind.EcdsaP384, KeyKind.EcdhP384, 4),
        PgpKeyProfile.NistP521 => (KeyKind.EcdsaP521, KeyKind.EcdhP521, 4),
        PgpKeyProfile.Rfc9980Pqc => (KeyKind.MlDsa65Ed25519, KeyKind.MlKem768X25519, 6),
        PgpKeyProfile.Rfc9980PqcHigh => (KeyKind.MlDsa87Ed448, KeyKind.MlKem1024X448, 6),
        _ => throw new ArgumentOutOfRangeException(nameof(profile)),
    };

    /// <summary>
    /// The preferences a new key advertises (RFC 9580 §5.2.3.14 to §5.2.3.22, §9): AES-256 and AES-128, SHA-512/256/384, no compression preference
    /// beyond zlib and zip, and for keys that read SEIPD v2 the AEAD suites. Keys of the older profiles stay at SEIPD v1 only.
    /// </summary>
    internal static List<SignatureSubpacket> Preferences(PgpKeyProfile profile)
    {
        bool modern = profile is not (PgpKeyProfile.Rfc4880Curve25519 or PgpKeyProfile.Rfc4880Rsa or PgpKeyProfile.NistP256 or PgpKeyProfile.NistP384 or PgpKeyProfile.NistP521);
        return Preferences(modern);
    }

    internal static List<SignatureSubpacket> Preferences(bool seipd2)
    {
        var list = new List<SignatureSubpacket>
        {
            SignatureSubpacket.Create((byte)SubpacketType.PreferredSymmetricAlgorithms, false, new[] { (byte)SymmetricAlgorithm.Aes256, (byte)SymmetricAlgorithm.Aes192, (byte)SymmetricAlgorithm.Aes128 }),
            SignatureSubpacket.Create((byte)SubpacketType.PreferredHashAlgorithms, false, new[] { (byte)PgpHashAlgorithm.Sha512, (byte)PgpHashAlgorithm.Sha256, (byte)PgpHashAlgorithm.Sha384 }),
            SignatureSubpacket.Create((byte)SubpacketType.PreferredCompressionAlgorithms, false, new[] { (byte)CompressionAlgorithm.Zlib, (byte)CompressionAlgorithm.Zip, (byte)CompressionAlgorithm.Uncompressed }),
            Subpackets.Features(seipd2 ? (byte)0x09 : (byte)0x01),
        };
        if (seipd2)
        {
            list.Add(SignatureSubpacket.Create((byte)SubpacketType.PreferredAeadCiphersuites, false,
                new[] { (byte)SymmetricAlgorithm.Aes256, (byte)AeadAlgorithm.Ocb, (byte)SymmetricAlgorithm.Aes128, (byte)AeadAlgorithm.Ocb }));
        }

        return list;
    }

    /// <summary>A freshly generated key: its public packet and the plain secret values as stored.</summary>
    internal sealed class NewKey
    {
        private NewKey(PublicKeyPacket pub, byte[] secret)
        {
            Public = pub;
            Secret = secret;
        }

        internal PublicKeyPacket Public { get; }

        internal byte[] Secret { get; }

        internal static NewKey Create(KeyKind kind, byte version, uint created, bool subkey)
        {
            (PublicKeyAlgorithm alg, byte[] material, byte[] secret) = Material(kind);
            return new NewKey(PublicKeyPacket.Create(version, created, alg, material, subkey), secret);
        }

        private static (PublicKeyAlgorithm, byte[], byte[]) Material(KeyKind kind)
        {
            switch (kind)
            {
                case KeyKind.Ed25519:
                    {
                        byte[] seed = RandomNumberGenerator.GetBytes(32);
                        byte[] pub = new byte[32];
                        Ed25519.DerivePublicKey(seed, pub);
                        return (PublicKeyAlgorithm.Ed25519, pub, seed);
                    }

                case KeyKind.X25519:
                    {
                        byte[] sk = RandomNumberGenerator.GetBytes(32);
                        byte[] pub = new byte[32];
                        X25519.DerivePublicKey(sk, pub);
                        return (PublicKeyAlgorithm.X25519, pub, sk);
                    }

                case KeyKind.Ed448:
                    {
                        byte[] seed = RandomNumberGenerator.GetBytes(57);
                        byte[] pub = new byte[57];
                        Ed448.DerivePublicKey(seed, pub);
                        return (PublicKeyAlgorithm.Ed448, pub, seed);
                    }

                case KeyKind.X448:
                    {
                        byte[] sk = RandomNumberGenerator.GetBytes(56);
                        byte[] pub = new byte[56];
                        X448.DerivePublicKey(sk, pub);
                        return (PublicKeyAlgorithm.X448, pub, sk);
                    }

                case KeyKind.EdDsaLegacy:
                    {
                        byte[] seed = RandomNumberGenerator.GetBytes(32);
                        byte[] pub = new byte[33];
                        pub[0] = 0x40;
                        Ed25519.DerivePublicKey(seed, pub.AsSpan(1));
                        return (PublicKeyAlgorithm.EdDsaLegacy, [.. OidField(SignatureEngine.Curves.Ed25519Legacy), .. SignatureEngine.Mpi(pub)], SignatureEngine.Mpi(seed));
                    }

                case KeyKind.EcdhCurve25519:
                    {
                        // RFC 9580 §5.5.5.6 (legacy Curve25519): the secret is clamped and stored as a big-endian MPI; the point is 0x40 and the public key.
                        byte[] sk = RandomNumberGenerator.GetBytes(32);
                        sk[0] &= 248;
                        sk[31] &= 127;
                        sk[31] |= 64;
                        byte[] pub = new byte[33];
                        pub[0] = 0x40;
                        X25519.DerivePublicKey(sk, pub.AsSpan(1));
                        Array.Reverse(sk);
                        byte[] secret = SignatureEngine.Mpi(sk);
                        CryptographicOperations.ZeroMemory(sk);
                        return (PublicKeyAlgorithm.Ecdh, [.. OidField(SignatureEngine.Curves.Curve25519Legacy), .. SignatureEngine.Mpi(pub), 3, 1, (byte)PgpHashAlgorithm.Sha256, (byte)SymmetricAlgorithm.Aes128], secret);
                    }

                case KeyKind.Rsa3072:
                    return Rsa(3072);
                case KeyKind.EcdsaP256:
                    return Nist(ECCurve.NamedCurves.nistP256, [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07], false, PgpHashAlgorithm.Sha256, SymmetricAlgorithm.Aes128);
                case KeyKind.EcdsaP384:
                    return Nist(ECCurve.NamedCurves.nistP384, [0x2B, 0x81, 0x04, 0x00, 0x22], false, PgpHashAlgorithm.Sha384, SymmetricAlgorithm.Aes256);
                case KeyKind.EcdsaP521:
                    return Nist(ECCurve.NamedCurves.nistP521, [0x2B, 0x81, 0x04, 0x00, 0x23], false, PgpHashAlgorithm.Sha512, SymmetricAlgorithm.Aes256);
                case KeyKind.EcdhP256:
                    return Nist(ECCurve.NamedCurves.nistP256, [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07], true, PgpHashAlgorithm.Sha256, SymmetricAlgorithm.Aes128);
                case KeyKind.EcdhP384:
                    return Nist(ECCurve.NamedCurves.nistP384, [0x2B, 0x81, 0x04, 0x00, 0x22], true, PgpHashAlgorithm.Sha384, SymmetricAlgorithm.Aes256);
                case KeyKind.EcdhP521:
                    return Nist(ECCurve.NamedCurves.nistP521, [0x2B, 0x81, 0x04, 0x00, 0x23], true, PgpHashAlgorithm.Sha512, SymmetricAlgorithm.Aes256);
                case KeyKind.MlDsa65Ed25519:
                case KeyKind.MlDsa87Ed448:
                    {
                        RecursiveAI.OneCrypto.Internal.Platform.RequireMlDsa();
                        bool small = kind == KeyKind.MlDsa65Ed25519;
                        byte[] seed = RandomNumberGenerator.GetBytes(small ? 32 : 57);
                        byte[] edPub = new byte[small ? 32 : 57];
                        if (small)
                        {
                            Ed25519.DerivePublicKey(seed, edPub);
                        }
                        else
                        {
                            Ed448.DerivePublicKey(seed, edPub);
                        }

                        using MLDsa ml = MLDsa.GenerateKey(small ? MLDsaAlgorithm.MLDsa65 : MLDsaAlgorithm.MLDsa87);
                        byte[] mlSeed = ml.ExportMLDsaPrivateSeed();
                        return (small ? PublicKeyAlgorithm.MlDsa65Ed25519 : PublicKeyAlgorithm.MlDsa87Ed448, [.. edPub, .. ml.ExportMLDsaPublicKey()], [.. seed, .. mlSeed]);
                    }

                case KeyKind.MlKem768X25519:
                case KeyKind.MlKem1024X448:
                    {
                        RecursiveAI.OneCrypto.Internal.Platform.RequireMlKem();
                        bool small = kind == KeyKind.MlKem768X25519;
                        byte[] sk = RandomNumberGenerator.GetBytes(small ? 32 : 56);
                        byte[] ecPub = new byte[small ? 32 : 56];
                        if (small)
                        {
                            X25519.DerivePublicKey(sk, ecPub);
                        }
                        else
                        {
                            X448.DerivePublicKey(sk, ecPub);
                        }

                        using MLKem kem = MLKem.GenerateKey(small ? MLKemAlgorithm.MLKem768 : MLKemAlgorithm.MLKem1024);
                        return (small ? PublicKeyAlgorithm.MlKem768X25519 : PublicKeyAlgorithm.MlKem1024X448, [.. ecPub, .. kem.ExportEncapsulationKey()], [.. sk, .. kem.ExportPrivateSeed()]);
                    }

                default:
                    throw new ArgumentOutOfRangeException(nameof(kind));
            }
        }

        private static byte[] OidField(byte[] oid) => [(byte)oid.Length, .. oid];

        private static (PublicKeyAlgorithm, byte[], byte[]) Nist(ECCurve curve, byte[] oid, bool ecdh, PgpHashAlgorithm kdfHash, SymmetricAlgorithm wrap)
        {
            ECParameters p;
            if (ecdh)
            {
                using var k = ECDiffieHellman.Create(curve);
                p = k.ExportParameters(true);
            }
            else
            {
                using var k = ECDsa.Create(curve);
                p = k.ExportParameters(true);
            }

            byte[] point = [4, .. p.Q.X!, .. p.Q.Y!];
            byte[] secret = SignatureEngine.Mpi(p.D!);
            CryptographicOperations.ZeroMemory(p.D!);
            byte[] material = [.. OidField(oid), .. SignatureEngine.Mpi(point)];
            if (ecdh)
            {
                material = [.. material, 3, 1, (byte)kdfHash, (byte)wrap];
            }

            return (ecdh ? PublicKeyAlgorithm.Ecdh : PublicKeyAlgorithm.Ecdsa, material, secret);
        }

        private static (PublicKeyAlgorithm, byte[], byte[]) Rsa(int bits)
        {
            // RFC 9580 §5.5.5.1 wants p < q and u = p^-1 mod q. The platform returns P, Q and InverseQ = Q^-1 mod P, so the stored p is the platform's Q,
            // the stored q its P and u its InverseQ; that only holds when the platform's Q is the smaller prime, so a key with the primes the other way
            // round is thrown away and another is made. The comparison is between two primes of a key that is discarded, not of one that is kept.
            for (int attempt = 0; attempt < 64; attempt++)
            {
                using var rsa = RSA.Create(bits);
                RSAParameters p = rsa.ExportParameters(true);
                if (!LessThan(p.Q!, p.P!))
                {
                    continue;
                }

                byte[] secret = [.. SignatureEngine.Mpi(p.D!), .. SignatureEngine.Mpi(p.Q!), .. SignatureEngine.Mpi(p.P!), .. SignatureEngine.Mpi(p.InverseQ!)];
                byte[] material = [.. SignatureEngine.Mpi(p.Modulus!), .. SignatureEngine.Mpi(p.Exponent!)];
                foreach (byte[]? part in new[] { p.D, p.P, p.Q, p.DP, p.DQ, p.InverseQ })
                {
                    CryptographicOperations.ZeroMemory(part);
                }

                return (PublicKeyAlgorithm.Rsa, material, secret);
            }

            throw new PgpException(PgpFailure.Unsupported, "The platform's RSA key generation kept returning the primes in the wrong order.");
        }

        private static bool LessThan(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return a.Length < b.Length;
            }

            return a.AsSpan().SequenceCompareTo(b) < 0;
        }
    }
}
