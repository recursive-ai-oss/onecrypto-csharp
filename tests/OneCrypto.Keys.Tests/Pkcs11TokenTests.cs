using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Keys.Pkcs11;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Keys.Tests;

/// <summary>The PKCS #11 backend against SoftHSM2: every key operation, then every failure it must report as a typed error.</summary>
public class Pkcs11TokenTests
{
    private static readonly byte[] Message = "a message signed by a key that never leaves the token"u8.ToArray();

    [Fact]
    public void TheModuleTheSlotsAndTheTokensAreDescribed()
    {
        SoftHsm.RequireOrSkip();
        using Pkcs11Module module = Pkcs11Module.Load(SoftHsm.Module!);
        Assert.True(module.Info.CryptokiVersion.Major >= 2);
        Assert.Contains("SoftHSM", module.Info.Manufacturer, StringComparison.OrdinalIgnoreCase);
        Pkcs11Slot slot = SoftHsm.SlotOf(module, SoftHsm.MainToken);
        Pkcs11TokenInfo t = slot.GetTokenInfo();
        Assert.True(t.LoginRequired && t.UserPinInitialized && t.Initialized);
        Assert.False(t.ProtectedAuthenticationPath);
        Assert.False(t.UserPinLocked);
        Assert.Contains(0x1UL, slot.GetMechanisms()); // CKM_RSA_PKCS
        Assert.True(module.GetSlots(tokenPresentOnly: false).Count >= module.GetSlots().Count);
    }

    // ---- RSA ----

    public static TheoryData<string> RsaSpecs => ["pkcs1-sha1", "pkcs1-sha256", "pkcs1-sha384", "pkcs1-sha512", "pss-sha256", "pss-sha384", "pss-sha512"];

    private static SignatureSpec RsaSpec(string name) => name.Split('-') switch
    {
        ["pkcs1", var h] => SignatureSpec.RsaPkcs1(Hash(h)),
        ["pss", var h] => SignatureSpec.RsaPss(Hash(h)),
        _ => throw new ArgumentException(name),
    };

    private static HashAlgorithmName Hash(string h) => h switch
    {
        "sha1" => HashAlgorithmName.SHA1,
        "sha256" => HashAlgorithmName.SHA256,
        "sha384" => HashAlgorithmName.SHA384,
        _ => HashAlgorithmName.SHA512,
    };

    [Theory]
    [MemberData(nameof(RsaSpecs))]
    public void ARsaKeyOnTheTokenSignsAndTheSignatureVerifies(string name)
    {
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open();
        using (module)
        using (session)
        {
            (string label, byte[] id) = SoftHsm.Fresh("rsa");
            IRsaKey key = Assert.IsAssignableFrom<IRsaKey>(session.GenerateKeyPair(Pkcs11KeyPairSpec.Rsa(2048), label, id));
            SignatureSpec spec = RsaSpec(name);
            Assert.True(key.Supports(spec));
            byte[] sig = key.Sign(Message, spec);
            Assert.Equal(256, sig.Length);
            Assert.True(spec.Verify(key.PublicKey, Message, sig).IsValid);
            Assert.False(spec.Verify(key.PublicKey, [.. Message, 0], sig).IsValid);

            // The digest form signs the same digest the message form hashed.
            byte[] digest = CryptographicOperations.HashData(spec.Hash, Message);
            Assert.True(spec.Verify(key.PublicKey, Message, key.SignDigest(digest, spec)).IsValid);
            Assert.Throws<ArgumentException>(() => key.SignDigest(digest.AsSpan(0, digest.Length - 1), spec));
            Assert.Equal(KeyCapabilities.Sign | KeyCapabilities.Decrypt, key.Capabilities);
        }
    }

    [Theory]
    [InlineData(DecryptionKind.RsaPkcs1, "")]
    [InlineData(DecryptionKind.RsaOaep, "sha1")]
    [InlineData(DecryptionKind.RsaOaep, "sha256")]
    public void ARsaKeyOnTheTokenDecrypts(DecryptionKind kind, string hash)
    {
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open();
        using (module)
        using (session)
        {
            (string label, byte[] id) = SoftHsm.Fresh("rsa-dec");
            IRsaKey key = Assert.IsAssignableFrom<IRsaKey>(session.GenerateKeyPair(Pkcs11KeyPairSpec.Rsa(2048), label, id));
            DecryptionSpec spec = kind == DecryptionKind.RsaPkcs1 ? DecryptionSpec.RsaPkcs1() : DecryptionSpec.RsaOaep(Hash(hash));
            byte[] secret = RandomNumberGenerator.GetBytes(32);
            using RSA pub = key.PublicKey.ToRsa();
            byte[] ct = kind == DecryptionKind.RsaPkcs1
                ? pub.Encrypt(secret, RSAEncryptionPadding.Pkcs1)
                : pub.Encrypt(secret, RSAEncryptionPadding.CreateOaep(Hash(hash)));
            try
            {
                Assert.Equal(secret, key.Decrypt(ct, spec));
            }
            catch (Pkcs11MechanismException)
            {
                // SoftHSM2 does OAEP with SHA-1 only; the refusal is a typed mechanism error, not a failed decryption.
                Assert.True(kind == DecryptionKind.RsaOaep && hash != "sha1");
                return;
            }

            // A damaged ciphertext never yields the secret. OAEP fails; PKCS #1 v1.5 may "succeed" with random bytes (implicit rejection).
            byte[] bad = (byte[])ct.Clone();
            bad[5] ^= 0x40;
            if (kind == DecryptionKind.RsaOaep)
            {
                CryptographicException e = Assert.ThrowsAny<CryptographicException>(() => key.Decrypt(bad, spec));
                Assert.False(e is Pkcs11Exception, "a failed decryption must not say why");
            }
            else
            {
                try
                {
                    Assert.NotEqual(secret, key.Decrypt(bad, spec));
                }
                catch (CryptographicException e)
                {
                    Assert.False(e is Pkcs11Exception);
                }
            }
        }
    }

    // ---- EC ----

    public static TheoryData<string> Curves => ["p256", "p384", "p521"];

    private static (Pkcs11KeyPairSpec Spec, ECCurve Curve, HashAlgorithmName Hash) CurveOf(string n) => n switch
    {
        "p256" => (Pkcs11KeyPairSpec.P256(), ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256),
        "p384" => (Pkcs11KeyPairSpec.P384(), ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384),
        _ => (Pkcs11KeyPairSpec.P521(), ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512),
    };

    [Theory]
    [MemberData(nameof(Curves))]
    public void AnEcKeyOnTheTokenSignsInBothEncodings(string curve)
    {
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open();
        using (module)
        using (session)
        {
            (string label, byte[] id) = SoftHsm.Fresh("ec");
            (Pkcs11KeyPairSpec ks, _, HashAlgorithmName h) = CurveOf(curve);
            ISigningKey key = Assert.IsAssignableFrom<ISigningKey>(session.GenerateKeyPair(ks, label, id));
            foreach (EcdsaSignatureFormat f in new[] { EcdsaSignatureFormat.Der, EcdsaSignatureFormat.Rfc4754 })
            {
                SignatureSpec spec = SignatureSpec.Ecdsa(h, f);
                byte[] sig = key.Sign(Message, spec);
                Assert.True(spec.Verify(key.PublicKey, Message, sig).IsValid, $"{curve} {f}");
                Assert.False(spec.Verify(key.PublicKey, "other"u8, sig).IsValid);
                if (f == EcdsaSignatureFormat.Rfc4754)
                {
                    Assert.Equal(2 * ((key.PublicKey.KeySizeBits + 7) / 8), sig.Length);
                }
            }

            // A hash that does not match the curve is still a legal ECDSA signature.
            SignatureSpec other = SignatureSpec.Ecdsa(HashAlgorithmName.SHA512);
            Assert.True(other.Verify(key.PublicKey, Message, key.Sign(Message, other)).IsValid);
        }
    }

    [Theory]
    [MemberData(nameof(Curves))]
    public void AnEcKeyOnTheTokenAgreesWithSoftware(string curve)
    {
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open();
        using (module)
        using (session)
        {
            (string label, byte[] id) = SoftHsm.Fresh("ecdh");
            (Pkcs11KeyPairSpec ks, ECCurve c, _) = CurveOf(curve);
            Pkcs11Key tk = session.GenerateKeyPair(ks, label, id);
            IAgreementKey key = Assert.IsAssignableFrom<IAgreementKey>(tk);
            Assert.True((tk.Capabilities & KeyCapabilities.Agree) != 0);

            using var peer = ECDiffieHellman.Create(c);
            byte[] fromToken = key.Agree(PublicKeyInfo.FromAsymmetricAlgorithm(peer));
            // The other side: the peer's private key with the token's public key.
            using var tokenPub = ECDiffieHellman.Create();
            tokenPub.ImportSubjectPublicKeyInfo(tk.PublicKey.Encoded.ToArray(), out _);
            Assert.Equal(peer.DeriveRawSecretAgreement(tokenPub.PublicKey), fromToken);

            // Another curve is refused before it reaches the token.
            using var wrong = ECDiffieHellman.Create(curve == "p256" ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.nistP256);
            Assert.Throws<ArgumentException>(() => key.Agree(PublicKeyInfo.FromAsymmetricAlgorithm(wrong)));
        }
    }

    // ---- Ed25519 ----

    [Fact]
    public void AnEd25519KeyOnTheTokenSignsWhereTheTokenHasIt()
    {
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open();
        using (module)
        using (session)
        {
            Assert.SkipUnless(session.Slot.GetMechanisms().Contains(0x1057) && session.Slot.GetMechanisms().Contains(0x1055), "the token has no EdDSA");
            (string label, byte[] id) = SoftHsm.Fresh("ed");
            ISigningKey key = Assert.IsAssignableFrom<ISigningKey>(session.GenerateKeyPair(Pkcs11KeyPairSpec.Ed25519(), label, id));
            Assert.Equal(KeyAlgorithm.Ed25519, key.PublicKey.KeyAlgorithm);
            SignatureSpec spec = SignatureSpec.Ed25519();
            byte[] sig = key.Sign(Message, spec);
            Assert.Equal(64, sig.Length);
            Assert.True(spec.Verify(key.PublicKey, Message, sig).IsValid);
            Assert.False(spec.Verify(key.PublicKey, "other"u8, sig).IsValid);
            Assert.Throws<NotSupportedException>(() => key.SignDigest(new byte[32], spec));
            Assert.False(key.Supports(SignatureSpec.Ed448()));
        }
    }

    // ---- the object store ----

    [Fact]
    public void CertificatesAreStoredFoundAndMatchTheirKey()
    {
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open();
        using (module)
        using (session)
        {
            (string label, byte[] id) = SoftHsm.Fresh("cert");
            Pkcs11Key key = session.GenerateKeyPair(Pkcs11KeyPairSpec.P256(), label, id);
            Certificate cert = TokenCertificates.SelfSigned("token cert", (ISigningKey)key, KeyUsages.DigitalSignature);
            session.ImportCertificate(cert, label, id);
            Pkcs11CertificateInfo found = Assert.Single(session.FindCertificates(label));
            Assert.Equal(cert.Encoded.ToArray(), found.Certificate.Encoded.ToArray());
            Assert.Equal(id, found.Id.ToArray());
            Assert.Equal(key.PublicKey, found.Certificate.PublicKey);
            Pkcs11KeyInfo info = Assert.Single(session.FindPrivateKeys(label));
            Assert.Equal(Pkcs11KeyType.EllipticCurve, info.KeyType);
            Assert.Equal(key.Handle, info.Handle);
            Assert.Empty(session.FindPrivateKeys("no such label"));
        }
    }

    [Fact]
    public void ASessionOpensTheSameKeyByLabelOrIdAndRefusesAmbiguity()
    {
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open();
        using (module)
        using (session)
        {
            (string label, byte[] id) = SoftHsm.Fresh("find");
            Pkcs11Key made = session.GenerateKeyPair(Pkcs11KeyPairSpec.P256(), label, id);
            Assert.Equal(made.PublicKey, session.OpenKey(label).PublicKey);
            Assert.Equal(made.PublicKey, session.OpenKey(id: id).PublicKey);
            Assert.Throws<ArgumentException>(() => session.OpenKey());

            // Two keys with one label: the library will not pick one.
            session.GenerateKeyPair(Pkcs11KeyPairSpec.P256(), label, new byte[] { id[0], id[1], 1 });
            Pkcs11KeyException e = Assert.Throws<Pkcs11KeyException>(() => session.OpenKey(label));
            Assert.Contains("2 private keys", e.Message, StringComparison.Ordinal);
            Assert.Equal(made.PublicKey, session.OpenKey(label, id).PublicKey);
        }
    }

    // ---- threads ----

    [Fact]
    public void OneSessionServesSeveralThreads()
    {
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open();
        using (module)
        using (session)
        {
            (string label, byte[] id) = SoftHsm.Fresh("threads");
            ISigningKey key = (ISigningKey)session.GenerateKeyPair(Pkcs11KeyPairSpec.P256(), label, id);
            SignatureSpec spec = SignatureSpec.Ecdsa(HashAlgorithmName.SHA256);
            int bad = 0;
            Parallel.For(0, 64, new ParallelOptions { MaxDegreeOfParallelism = 8 }, i =>
            {
                byte[] m = BitConverter.GetBytes(i);
                if (!spec.Verify(key.PublicKey, m, key.Sign(m, spec)).IsValid)
                {
                    Interlocked.Increment(ref bad);
                }
            });
            Assert.Equal(0, bad);
        }
    }

    // ---- failures ----

    [Fact]
    public void AWrongPinIsATypedError()
    {
        SoftHsm.RequireOrSkip();
        using Pkcs11Module module = Pkcs11Module.Load(SoftHsm.Module!);
        using Pkcs11Session s = SoftHsm.SlotOf(module, SoftHsm.AuthToken).OpenSession(readWrite: true);
        Pkcs11PinException e = Assert.Throws<Pkcs11PinException>(() => s.Login("0000"));
        Assert.Equal(Pkcs11Result.PinIncorrect, e.Result);
        Assert.Equal("C_Login", e.Function);
        Assert.False(s.IsLoggedIn);
        Assert.IsNotType<Pkcs11PinLockedException>(e);
        Assert.Throws<ArgumentException>(() => s.Login(""));
        Assert.Throws<Pkcs11PinException>(() => s.LoginProtectedAuthenticationPath()); // the token has no protected path
        s.Login(SoftHsm.UserPin); // the right PIN still works afterwards
        Assert.True(s.IsLoggedIn);
        s.Login(SoftHsm.UserPin); // and logging in again is not an error
    }

    [Fact]
    public void APinOfTheWrongLengthIsATypedError()
    {
        SoftHsm.RequireOrSkip();
        using Pkcs11Module module = Pkcs11Module.Load(SoftHsm.Module!);
        using Pkcs11Session s = SoftHsm.SlotOf(module, SoftHsm.AuthToken).OpenSession(readWrite: true);
        Pkcs11PinException e = Assert.Throws<Pkcs11PinException>(() => s.Login("12"));
        Assert.True(e.Result is Pkcs11Result.PinLenRange or Pkcs11Result.PinIncorrect); // tokens differ on which of the two they answer
        Assert.False(s.IsLoggedIn);
    }

    // SoftHSM2 never locks a user PIN (40 wrong attempts leave the token usable, as the run of this suite showed), so a locked token cannot be
    // made on it. What a token reports when it is locked is mapped by the same code every call uses, and is checked there.
    [Theory]
    [InlineData(0xA4u, typeof(Pkcs11PinLockedException))]
    [InlineData(0xA0u, typeof(Pkcs11PinException))]
    [InlineData(0xA3u, typeof(Pkcs11PinException))]
    [InlineData(0x70u, typeof(Pkcs11MechanismException))]
    [InlineData(0x32u, typeof(Pkcs11TokenException))]
    [InlineData(0xE0u, typeof(Pkcs11TokenException))]
    [InlineData(0x82u, typeof(Pkcs11KeyException))]
    [InlineData(0x80000001u, typeof(Pkcs11Exception))]
    public void ModuleReturnValuesBecomeTypedErrors(uint rv, Type expected)
    {
        Pkcs11Exception e = Pkcs11Errors.For("C_Login", rv);
        Assert.Equal(expected, e.GetType());
        Assert.Equal(rv, e.ReturnCode);
        Assert.Equal("C_Login", e.Function);
        Assert.IsAssignableFrom<CryptographicException>(e);
        Assert.IsType<Pkcs11PinLockedException>(Pkcs11Errors.For("C_Login", 0xA4));
        Assert.IsAssignableFrom<Pkcs11PinException>(Pkcs11Errors.For("C_Login", 0xA4)); // a locked PIN is also a refused PIN
    }

    [Fact]
    public void AnUnknownMechanismIsATypedError()
    {
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open();
        using (module)
        using (session)
        {
            (string label, byte[] id) = SoftHsm.Fresh("mech");
            Pkcs11Key key = session.GenerateKeyPair(Pkcs11KeyPairSpec.Rsa(2048), label, id);
            Pkcs11MechanismException e = Assert.Throws<Pkcs11MechanismException>(() => session.SignRaw(key, 0xDEADBEEF, null, Message));
            Assert.Equal(Pkcs11Result.MechanismInvalid, e.Result);
            Assert.Equal("C_SignInit", e.Function);
            // The session is usable afterwards.
            Assert.True(((ISigningKey)key).Sign(Message, SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256)).Length == 256);
        }
    }

    [Fact]
    public void AMechanismTheTokenDoesNotListIsNotSupportedBeforeTheTokenIsAsked()
    {
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open();
        using (module)
        using (session)
        {
            Assert.SkipWhen(session.Slot.GetMechanisms().Contains(0x1057), "this token has EdDSA");
            // A token without EdDSA cannot make an Ed25519 key pair either.
            AlgorithmNotSupportedException e = Assert.Throws<AlgorithmNotSupportedException>(() => session.GenerateKeyPair(Pkcs11KeyPairSpec.Ed25519(), "x", new byte[] { 1 }));
            Assert.Contains("0x1055", e.Message, StringComparison.Ordinal);
            Assert.Contains("token", e.Platform, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ANonexistentOrWrongModuleIsATypedError()
    {
        SoftHsm.RequireOrSkip();
        string missing = Path.Combine(SoftHsm.Work, "no-such-module.so");
        Pkcs11ModuleException e = Assert.Throws<Pkcs11ModuleException>(() => Pkcs11Module.Load(missing));
        Assert.Equal(missing, e.ModulePath);
        Assert.Contains("does not exist", e.Message, StringComparison.Ordinal);

        string notAModule = Path.Combine(SoftHsm.Work, "not-a-module.so");
        File.WriteAllText(notAModule, "this is not a shared library");
        Assert.Throws<Pkcs11ModuleException>(() => Pkcs11Module.Load(notAModule));

        // A real library that is not a PKCS #11 module (the C library, found through the loader).
        Assert.Throws<Pkcs11ModuleException>(() => Pkcs11Module.Load(OperatingSystem.IsMacOS() ? "libSystem.B.dylib" : "libc.so.6"));
        Assert.Throws<ArgumentException>(() => Pkcs11Module.Load(""));
    }

    [Fact]
    public void ARemovedKeyIsATypedErrorOnTheNextUse()
    {
        SoftHsm.RequireOrSkip();
        using Pkcs11Module module = Pkcs11Module.Load(SoftHsm.Module!);
        Pkcs11Slot slot = SoftHsm.SlotOf(module, SoftHsm.MainToken);
        (string label, byte[] id) = SoftHsm.Fresh("removed");
        using Pkcs11Session writer = slot.OpenSession(readWrite: true);
        writer.Login(SoftHsm.UserPin);
        using Pkcs11Session reader = slot.OpenSession();
        reader.Login(SoftHsm.UserPin);
        Pkcs11Key made = writer.GenerateKeyPair(Pkcs11KeyPairSpec.P256(), label, id);
        ISigningKey inReader = (ISigningKey)reader.OpenKey(label);
        SignatureSpec spec = SignatureSpec.Ecdsa(HashAlgorithmName.SHA256);
        Assert.True(spec.Verify(inReader.PublicKey, Message, inReader.Sign(Message, spec)).IsValid);

        writer.Destroy(made);
        Pkcs11KeyException e = Assert.Throws<Pkcs11KeyException>(() => inReader.Sign(Message, spec));
        Assert.True(e.Result is Pkcs11Result.ObjectHandleInvalid or Pkcs11Result.KeyHandleInvalid);
        Assert.Throws<Pkcs11KeyException>(() => reader.OpenKey(label));
        Assert.Empty(writer.FindPrivateKeys(label));
    }

    [Fact]
    public void AReadOnlySessionCannotWriteAndALoggedOutSessionSeesNoKeys()
    {
        SoftHsm.RequireOrSkip();
        using Pkcs11Module module = Pkcs11Module.Load(SoftHsm.Module!);
        Pkcs11Slot slot = SoftHsm.SlotOf(module, SoftHsm.AuthToken);
        using Pkcs11Session ro = slot.OpenSession();
        ro.Login(SoftHsm.UserPin);
        (string label, byte[] id) = SoftHsm.Fresh("ro");
        Assert.ThrowsAny<Pkcs11Exception>(() => ro.GenerateKeyPair(Pkcs11KeyPairSpec.P256(), label, id));

        using Pkcs11Session rw = slot.OpenSession(readWrite: true);
        rw.Login(SoftHsm.UserPin);
        rw.GenerateKeyPair(Pkcs11KeyPairSpec.P256(), label, id);
        // The login belongs to the token: logging out in one session closes the private objects to all of them.
        Assert.True(rw.IsLoggedIn);
        ro.Logout();
        Assert.False(ro.IsLoggedIn);
        Assert.False(rw.IsLoggedIn);
        Pkcs11KeyException e = Assert.Throws<Pkcs11KeyException>(() => rw.OpenKey(label));
        Assert.Contains("not logged in", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void DisposedSessionsAndModulesRefuseWork()
    {
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open();
        (string label, byte[] id) = SoftHsm.Fresh("disposed");
        Pkcs11Key key = session.GenerateKeyPair(Pkcs11KeyPairSpec.P256(), label, id);
        SignatureSpec spec = SignatureSpec.Ecdsa(HashAlgorithmName.SHA256);
        module.Dispose(); // closes the sessions too
        Assert.Throws<ObjectDisposedException>(() => ((ISigningKey)key).Sign(Message, spec));
        Assert.Throws<ObjectDisposedException>(() => session.OpenKey(label));
        Assert.Throws<ObjectDisposedException>(() => module.GetSlots());
        module.Dispose(); // twice is fine
    }

    [Fact]
    public async Task TheAsyncFormsRunAndHonourCancellation()
    {
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open();
        using (module)
        using (session)
        {
            (string label, byte[] id) = SoftHsm.Fresh("async");
            ISigningKey key = (ISigningKey)session.GenerateKeyPair(Pkcs11KeyPairSpec.P256(), label, id);
            SignatureSpec spec = SignatureSpec.Ecdsa(HashAlgorithmName.SHA256);
            byte[] sig = await key.SignAsync(Message, spec);
            Assert.True(spec.Verify(key.PublicKey, Message, sig).IsValid);
            using var cts = new CancellationTokenSource();
            await cts.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await key.SignAsync(Message, spec, cts.Token));
        }
    }
}
