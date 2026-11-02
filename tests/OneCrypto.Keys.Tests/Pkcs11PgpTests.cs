using System.Numerics;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Keys.Pkcs11;
using RecursiveAI.OneCrypto.OpenPgp;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Keys.Tests;

/// <summary>
/// OpenPGP with keys on the token. A certificate is generated with the library, its secret keys are imported into SoftHSM2 with softhsm2-util
/// (the tool's own import, so the token is filled the way an administrator fills one), and the library then signs and decrypts through the token.
/// </summary>
public class Pkcs11PgpTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly byte[] Data = RandomNumberGenerator.GetBytes(50_000);

    public static TheoryData<PgpKeyProfile> Profiles => [PgpKeyProfile.Rfc4880Rsa, PgpKeyProfile.NistP256, PgpKeyProfile.Rfc9580];

    internal sealed record Imported(PgpCertificate Secret, PgpCertificate Public, string Dir);

    private static string Dir(string name)
    {
        string d = Path.Combine(SoftHsm.Work, "pgp", name);
        Directory.CreateDirectory(d);
        return d;
    }

    private static string LabelOf(int keyIndex, string run) => $"pgp-{run}-{keyIndex}";

    /// <summary>Generates the certificate and puts every secret key that has a token form (RSA, NIST ECDSA/ECDH, Ed25519) into the import token.</summary>
    internal static Imported Import(PgpKeyProfile profile, out string run)
    {
        SoftHsm.RequireOrSkip();
        run = SoftHsm.Fresh("pgp").Label;
        PgpCertificate secret = PgpKeyGenerator.Generate(new PgpKeyGenerationOptions { Now = Now, UserIds = ["Token Test <token@example.org>"], Profile = profile });
        string dir = Dir(run);
        for (int i = 0; i < secret.Keys.Count; i++)
        {
            byte[]? pkcs8 = Pkcs8Of(secret.Keys[i]);
            if (pkcs8 is null)
            {
                continue;
            }

            string file = Path.Combine(dir, $"key{i}.pem");
            File.WriteAllText(file, Tools.Pem("PRIVATE KEY", pkcs8));
            var r = SoftHsm.Util_("--import", file, "--token", "u-import", "--label", LabelOf(i, run), "--id", $"{i:X2}{run.GetHashCode():X8}", "--pin", SoftHsm.UserPin);
            Assert.True(r.Code == 0, "softhsm2-util --import: " + r.Output);
        }

        return new Imported(secret, secret.ToPublicCertificate(), dir);
    }

    /// <summary>The PKCS #8 form of an OpenPGP secret key, for the algorithms a token holds; null for the rest.</summary>
    private static byte[]? Pkcs8Of(PgpKey key)
    {
        using PgpSecretKey unlocked = PgpSecretKey.Unlock(key);
        List<byte[]> parts = unlocked.SecretParts();
        var material = key.Packet.Material;
        switch (key.Algorithm)
        {
            case PublicKeyAlgorithm.Rsa:
                {
                    // OpenPGP keeps d, p, q, u with p < q and u = p^-1 mod q; the platform names them P, Q, InverseQ with InverseQ = Q^-1 mod P.
                    BigInteger d = Big(parts[0]), p = Big(parts[1]), q = Big(parts[2]);
                    byte[] n = material.Values[0].ToArray();
                    int half = (n.Length + 1) / 2;
                    var prm = new RSAParameters
                    {
                        Modulus = n,
                        Exponent = material.Values[1].ToArray(),
                        D = Fixed(d, n.Length),
                        P = Fixed(q, half),
                        Q = Fixed(p, half),
                        DP = Fixed(d % (q - 1), half),
                        DQ = Fixed(d % (p - 1), half),
                        InverseQ = Fixed(Big(parts[3]), half),
                    };
                    using var rsa = RSA.Create();
                    rsa.ImportParameters(prm);
                    return rsa.ExportPkcs8PrivateKey();
                }

            case PublicKeyAlgorithm.Ecdsa or PublicKeyAlgorithm.Ecdh when material.Values[0].Length == 65:
                {
                    ReadOnlySpan<byte> q = material.Values[0].Span;
                    using var ec = ECDsa.Create(new ECParameters
                    {
                        Curve = ECCurve.NamedCurves.nistP256,
                        D = Fixed(Big(parts[0]), 32),
                        Q = new ECPoint { X = q.Slice(1, 32).ToArray(), Y = q.Slice(33, 32).ToArray() },
                    });
                    return ec.ExportPkcs8PrivateKey();
                }

            case PublicKeyAlgorithm.Ed25519:
                // RFC 8410 §7: PrivateKeyInfo with id-Ed25519 and the 32-octet seed in an inner OCTET STRING.
                return [.. Convert.FromHexString("302e020100300506032b657004220420"), .. parts[0]];
            default:
                return null;
        }
    }

    private static BigInteger Big(byte[] v) => new(v, isUnsigned: true, isBigEndian: true);

    private static byte[] Fixed(BigInteger v, int size)
    {
        byte[] b = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] r = new byte[size];
        b.CopyTo(r, size - b.Length);
        return r;
    }

    /// <summary>Opens the token key that belongs to an OpenPGP key.</summary>
    internal static Pkcs11Key Open(Pkcs11Session session, Imported imp, string run, int index)
    {
        PgpKey key = imp.Secret.Keys[index];
        PublicKeyInfo? pub = null;
        using (PgpSecretKey unlocked = PgpSecretKey.Unlock(key))
        {
            List<byte[]> parts = unlocked.SecretParts();
            var material = key.Packet.Material;
            if (key.Algorithm is PublicKeyAlgorithm.Ecdsa or PublicKeyAlgorithm.Ecdh)
            {
                ReadOnlySpan<byte> q = material.Values[0].Span;
                using var ec = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = q.Slice(1, 32).ToArray(), Y = q.Slice(33, 32).ToArray() } });
                pub = PublicKeyInfo.FromAsymmetricAlgorithm(ec);
            }
            else if (key.Algorithm == PublicKeyAlgorithm.Ed25519)
            {
                using ISigningKey ed = PrivateKey.FromEd25519(Ed25519PrivateKey.FromSeed(parts[0]), ownsKey: true);
                pub = ed.PublicKey;
            }
        }

        // softhsm2-util imports keys without the right to derive; ECDH decryption needs it, so the way an administrator would enable it is done here.
        Pkcs11Key opened = session.OpenKey(LabelOf(index, run), publicKey: pub);
        if (key.Algorithm == PublicKeyAlgorithm.Ecdh)
        {
            Raw.SetBool(session.Module, session.Handle, (nuint)opened.Handle, 0x10C, true);
            opened = session.OpenKey(LabelOf(index, run), publicKey: pub);
        }

        return opened;
    }

    // ---- signing ----

    [Theory]
    [MemberData(nameof(Profiles))]
    public void ASignatureMadeWithATokenKeyVerifiesHereAndInSequoia(PgpKeyProfile profile)
    {
        Imported imp = Import(profile, out string run);
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open("u-import");
        using (module)
        using (session)
        {
            Pkcs11Key token = Open(session, imp, run, 0);
            using PgpSecretKey signer = PgpSecretKey.FromExternal(imp.Public.Primary, token);
            using var data = new MemoryStream(Data);
            using var sig = new MemoryStream();
            PgpMessageWriter.SignDetached(data, sig, new PgpWriteOptions { Now = Now, Signers = [signer], Armor = true });

            var result = PgpMessageReader.VerifyDetached(new MemoryStream(Data), new MemoryStream(sig.ToArray()), new PgpReadOptions { Now = Now.AddMinutes(1), Certificates = [imp.Public] });
            Assert.Contains(result.Signatures, s => s.IsValid);
            var tampered = PgpMessageReader.VerifyDetached(new MemoryStream([.. Data, 0]), new MemoryStream(sig.ToArray()), new PgpReadOptions { Now = Now.AddMinutes(1), Certificates = [imp.Public] });
            Assert.DoesNotContain(tampered.Signatures, s => s.IsValid);

            Tools.RequireSqop();
            File.WriteAllBytes(Path.Combine(imp.Dir, "data.bin"), Data);
            File.WriteAllBytes(Path.Combine(imp.Dir, "sig.asc"), sig.ToArray());
            File.WriteAllBytes(Path.Combine(imp.Dir, "cert.pgp"), imp.Public.ExportPublic(armor: true));
            var r = Tools.Run(Tools.Sqop!, Path.Combine(imp.Dir, "data.bin"), "verify", Path.Combine(imp.Dir, "sig.asc"), Path.Combine(imp.Dir, "cert.pgp"));
            Assert.True(r.Code == 0, $"sqop verify ({profile}): {r.Error}");
        }
    }

    [Fact]
    public void AMessageSignedAndEncryptedWithATokenSignerReadsBack()
    {
        Imported imp = Import(PgpKeyProfile.NistP256, out string run);
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open("u-import");
        using (module)
        using (session)
        {
            using PgpSecretKey signer = PgpSecretKey.FromExternal(imp.Public.Primary, Open(session, imp, run, 0));
            using var enc = new MemoryStream();
            PgpMessageWriter.Write(new MemoryStream(Data), enc, new PgpWriteOptions { Now = Now, Signers = [signer], Recipients = [imp.Public] });

            using PgpSecretKey decryptor = PgpSecretKey.FromExternal(imp.Public.Keys[1], Open(session, imp, run, 1));
            using var plain = new MemoryStream();
            PgpReadResult r = PgpMessageReader.Read(new MemoryStream(enc.ToArray()), plain, new PgpReadOptions { Now = Now.AddMinutes(1), Certificates = [imp.Public], ExternalKeys = [decryptor] });
            Assert.Equal(Data, plain.ToArray());
            Assert.True(r.WasEncrypted);
            Assert.Contains(r.Signatures, s => s.IsValid);
        }
    }

    // ---- decryption ----

    [Theory]
    [InlineData(PgpKeyProfile.Rfc4880Rsa)]
    [InlineData(PgpKeyProfile.NistP256)]
    public void AnOpenPgpMessageIsDecryptedByTheToken(PgpKeyProfile profile)
    {
        Imported imp = Import(profile, out string run);
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open("u-import");
        using (module)
        using (session)
        {
            PgpKey subkey = imp.Secret.Keys[1];
            Pkcs11Key token = Open(session, imp, run, 1);
            using PgpSecretKey ext = PgpSecretKey.FromExternal(imp.Public.Keys[1], token);
            var options = new PgpReadOptions { Now = Now.AddMinutes(1), ExternalKeys = [ext] };

            // Written by this library.
            using var enc = new MemoryStream();
            PgpMessageWriter.Write(new MemoryStream(Data), enc, new PgpWriteOptions { Now = Now, Recipients = [imp.Public] });
            using var plain = new MemoryStream();
            PgpMessageReader.Read(new MemoryStream(enc.ToArray()), plain, options);
            Assert.Equal(Data, plain.ToArray());
            Assert.NotNull(subkey);

            // A key that is not the message's recipient is refused, as it is without a token.
            PgpCertificate other = PgpKeyGenerator.Generate(new PgpKeyGenerationOptions { Now = Now, UserIds = ["Other <other@example.org>"], Profile = profile });
            using var otherEnc = new MemoryStream();
            PgpMessageWriter.Write(new MemoryStream(Data), otherEnc, new PgpWriteOptions { Now = Now, Recipients = [other.ToPublicCertificate()] });
            Assert.ThrowsAny<PgpException>(() => PgpMessageReader.Read(new MemoryStream(otherEnc.ToArray()), new MemoryStream(), options));

            // Written by Sequoia.
            if (Tools.Sqop is not null)
            {
                File.WriteAllBytes(Path.Combine(imp.Dir, "data.bin"), Data);
                File.WriteAllBytes(Path.Combine(imp.Dir, "cert.pgp"), imp.Public.ExportPublic(armor: true));
                var r = Tools.Run(Tools.Sqop, Path.Combine(imp.Dir, "data.bin"), "encrypt", "--as=binary", Path.Combine(imp.Dir, "cert.pgp"));
                Assert.True(r.Code == 0, "sqop encrypt: " + r.Error);
                using var plain2 = new MemoryStream();
                PgpMessageReader.Read(new MemoryStream(r.Out), plain2, options);
                Assert.Equal(Data, plain2.ToArray());
            }
        }
    }
}
