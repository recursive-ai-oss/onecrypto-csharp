using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.OpenPgp.GnuPG;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Primitives;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

public class GnuPGKeyFileTests
{
    internal const string Passphrase = "onecrypto-test";

    /// <summary>The public keys of a home's keybox, indexed by the public value a key file shares with them (RSA modulus or EC point).</summary>
    internal static Dictionary<string, KeyPacket> PublicIndex(string version, string home = "main")
    {
        var map = new Dictionary<string, KeyPacket>(StringComparer.Ordinal);
        foreach (KeyboxOpenPgpBlob b in Keybox.Parse(File.ReadAllBytes(GnuPGHomes.Dir(version, home, "pubring.kbx"))).OpenPgpBlobs)
        {
            TransferableKey k = b.ReadKey();
            foreach (KeyPacket p in new[] { k.Primary }.Concat(k.Subkeys.Select(s => s.Key)))
            {
                if (p.Material.Values.Count > 0)
                {
                    map[Hex(p.Material.Values[0].Span)] = p; // RSA: n; EC: the point
                }
            }
        }

        return map;
    }

    internal static string Hex(ReadOnlySpan<byte> v)
    {
        while (v.Length > 0 && v[0] == 0)
        {
            v = v[1..];
        }

        return Convert.ToHexString(v);
    }

    internal static string KeyIndex(GnuPGKeyFile f) => Hex(f.Algorithm == "rsa" ? f.GetPublicParameter("n").Span : f.GetPublicParameter("q").Span);

    public static IEnumerable<object[]> KeyFiles()
    {
        foreach (string v in GnuPGHomes.Versions)
        {
            foreach (string home in new[] { "main", "special" })
            {
                string dir = GnuPGHomes.Dir(v, home, "private-keys-v1.d");
                if (Directory.Exists(dir))
                {
                    foreach (string f in Directory.GetFiles(dir, "*.key").Order(StringComparer.Ordinal))
                    {
                        yield return new object[] { v, home, Path.GetFileName(f) };
                    }
                }
            }
        }
    }

    [Theory]
    [MemberData(nameof(KeyFiles))]
    public void KeyFilesOpenAndMatchTheirOpenPgpPublicKeys(string version, string home, string file)
    {
        GnuPGKeyFile kf = GnuPGKeyFile.Parse(File.ReadAllBytes(GnuPGHomes.Dir(version, home, "private-keys-v1.d", file)));
        Assert.Equal(file[..^4], Path.GetFileNameWithoutExtension(file));
        Assert.NotNull(kf.Created);

        var index = PublicIndex(version, home);
        if (!index.TryGetValue(KeyIndex(kf), out KeyPacket? pub))
        {
            // A key whose certificate is not in this home's keybox as a key of its own (the ECC half of a Kyber subkey); nothing to compare.
            Assert.Equal("special", home);
            return;
        }

        Assert.Equal(kf.IsProtected, kf.Protection != GnuPGKeyProtection.None);
        using GnuPGSecretKey secret = kf.Unlock(kf.IsProtected ? Passphrase : string.Empty);
        KeyProofs.Check(secret, kf, pub);
    }

    [Fact]
    public void EveryGnuPGVersionWritesOcbProtectedKeysAndTheExpectedMix()
    {
        foreach (string v in GnuPGHomes.Versions)
        {
            var files = Directory.GetFiles(GnuPGHomes.Dir(v, "main", "private-keys-v1.d"), "*.key").Select(f => GnuPGKeyFile.Parse(File.ReadAllBytes(f))).ToList();
            Assert.Contains(files, f => f.Protection == GnuPGKeyProtection.None);
            Assert.Contains(files, f => f.Protection == GnuPGKeyProtection.OcbAes);
            Assert.DoesNotContain(files, f => f.Protection is GnuPGKeyProtection.Unknown or GnuPGKeyProtection.OpenPgpNative);
            Assert.Contains(files, f => f.Algorithm == "rsa");
            Assert.Contains(files, f => f.Curve == "Ed25519");
            Assert.Contains(files, f => f.Curve == "Cv25519" || f.Curve == "Curve25519");
        }
    }

    [Theory]
    [InlineData("rsa")]
    [InlineData("nistp256")]
    [InlineData("nistp384")]
    [InlineData("brainpoolp256r1")]
    public void KeysProtectedWithAesCbcAndSha1Open(string name)
    {
        string dir = Path.Combine(GnuPGHomes.Root, "cbc");
        GnuPGKeyFile kf = GnuPGKeyFile.Parse(File.ReadAllBytes(Path.Combine(dir, name + ".key")));
        Assert.Equal(GnuPGKeyProtection.Sha1AesCbc, kf.Protection);
        GnuPGKeyFile clear = GnuPGKeyFile.Parse(File.ReadAllBytes(Path.Combine(dir, name + ".clear.key")));
        Assert.Equal(GnuPGKeyProtection.None, clear.Protection);
        Assert.Equal(KeyIndex(clear), KeyIndex(kf));

        var index = PublicIndex("2.4.8");
        KeyPacket pub = index[KeyIndex(kf)];
        using GnuPGSecretKey secret = kf.Unlock(Passphrase);
        KeyProofs.Check(secret, kf, pub);
        Assert.Throws<GnuPGWrongPassphraseException>(() => kf.Unlock("wrong"));
    }

    [Fact]
    public void AWrongPassphraseIsATypedErrorForEveryMode()
    {
        foreach (string v in GnuPGHomes.Versions)
        {
            foreach (string f in Directory.GetFiles(GnuPGHomes.Dir(v, "main", "private-keys-v1.d"), "*.key"))
            {
                GnuPGKeyFile kf = GnuPGKeyFile.Parse(File.ReadAllBytes(f));
                if (kf.IsProtected)
                {
                    Assert.Throws<GnuPGWrongPassphraseException>(() => kf.Unlock("not the passphrase"));
                    Assert.Throws<GnuPGWrongPassphraseException>(() => kf.Unlock(string.Empty));
                }
            }
        }
    }

    [Fact]
    public void AnS2kCountBeyondTheLimitIsRefusedBeforeAnyWork()
    {
        string path = Directory.GetFiles(GnuPGHomes.Dir("2.4.8", "main", "private-keys-v1.d"), "*.key").First(f => GnuPGKeyFile.Parse(File.ReadAllBytes(f)).IsProtected);
        string text = File.ReadAllText(path, Encoding.Latin1);
        string patched = System.Text.RegularExpressions.Regex.Replace(text, "\"\\d+\"\\)", "\"99999999999\")");
        Assert.NotEqual(text, patched);
        GnuPGKeyFile kf = GnuPGKeyFile.Parse(Encoding.Latin1.GetBytes(patched));
        var ex = Assert.Throws<KdfLimitExceededException>(() => kf.Unlock(Passphrase));
        Assert.Equal(99999999999, ex.Requested);
        Assert.Throws<KdfLimitExceededException>(() => kf.Unlock(Passphrase, new GnuPGLimits { MaxS2kCount = 1000 }));
    }

    [Fact]
    public void ExtendedFormatHeadersAreRead()
    {
        string path = Directory.GetFiles(GnuPGHomes.Dir("2.4.8", "main", "private-keys-v1.d"), "*.key")[0];
        GnuPGKeyFile kf = GnuPGKeyFile.Parse(File.ReadAllBytes(path));
        Assert.Equal("Created", kf.Headers[0].Key);
        Assert.Equal("Key", kf.Headers[1].Key);
        Assert.Equal(DateTimeOffset.UtcNow.Year, kf.Created!.Value.Year);

        string custom = "# a comment\nDescription: Key for\n  signing\nCreated: 20200102T030405\nUse-for-ssh: yes\nKey: (private-key (dsa (p #0B#)(q #05#)(g #02#)(y #04#)(x #03#)))\n";
        GnuPGKeyFile k2 = GnuPGKeyFile.Parse(Encoding.UTF8.GetBytes(custom));
        Assert.Equal("Key for signing", k2.Description?.Replace("  ", " ", StringComparison.Ordinal));
        Assert.Equal(new DateTimeOffset(2020, 1, 2, 3, 4, 5, TimeSpan.Zero), k2.Created);
        Assert.Equal("yes", k2.GetHeader("use-for-ssh"));
        Assert.Equal("dsa", k2.Algorithm);
        Assert.Equal(new byte[] { 0x0B }, k2.GetPublicParameter("p").ToArray());
    }

    [Fact]
    public void ShadowedKeysAreRecognisedAndRefuseToUnlock()
    {
        string shadow = "Token: D2760001240102000005000011730000 OPENPGP.1 -\nKey: (shadowed-private-key (rsa (n #00AA#)(e #010001#)(shadowed t1-v1 (#D2760001240102000005000011730000# OPENPGP.1))))\n";
        GnuPGKeyFile kf = GnuPGKeyFile.Parse(Encoding.UTF8.GetBytes(shadow));
        Assert.Equal(GnuPGKeyProtection.Shadowed, kf.Protection);
        Assert.StartsWith("D2760001", kf.Token, StringComparison.Ordinal);
        Assert.Throws<NotSupportedException>(() => kf.Unlock(string.Empty));
    }

    [Fact]
    public void CanonicalFormIsReadToo()
    {
        // The canonical form GnuPG 2.0 wrote: no headers, lengths instead of delimiters.
        byte[] can = Encoding.Latin1.GetBytes("(11:private-key(3:dsa(1:p1:\x0B)(1:q1:\x05)(1:g1:\x02)(1:y1:\x04)(1:x1:\x03)))");
        GnuPGKeyFile kf = GnuPGKeyFile.Parse(can);
        Assert.Equal("dsa", kf.Algorithm);
        Assert.Empty(kf.Headers);
    }

    [Fact]
    public void MalformedKeyFilesAreTypedErrors()
    {
        foreach (string bad in new[]
        {
            string.Empty,
            "(",
            "(private-key",
            "Key: (private-key (rsa (n #0#)))",
            "Created: x\n",
            "Key: (public-key (rsa (n #00#)))",
            "Key: (private-key (rsa (n #00#))) \nKey: (private-key (rsa (n #00#)))",
            "(private-key (rsa (n 99999999999:ab)))",
            "(private-key (rsa (n \"abc)))",
            " leading space\nKey: (private-key (rsa (n #00#)))",
            "Key: " + new string('(', 100) + new string(')', 100),
        })
        {
            Assert.False(GnuPGKeyFile.TryParse(Encoding.UTF8.GetBytes(bad), out _, out GnuPGFailure f), bad);
            Assert.NotEqual(default, f);
        }

        Assert.False(GnuPGKeyFile.TryParse(new byte[2 << 20], out _, out GnuPGFailure big));
        Assert.Equal(GnuPGError.LimitExceeded, big.Error);
    }

    [Fact]
    public void EveryTruncationAndByteFlipOfAProtectedKeyIsATypedResult()
    {
        string path = Directory.GetFiles(GnuPGHomes.Dir("2.4.8", "main", "private-keys-v1.d"), "*.key").First(f => f.Contains("", StringComparison.Ordinal) && GnuPGKeyFile.Parse(File.ReadAllBytes(f)).Algorithm == "ecc" && GnuPGKeyFile.Parse(File.ReadAllBytes(f)).IsProtected);
        byte[] good = File.ReadAllBytes(path);
        for (int len = 0; len < good.Length; len++)
        {
            _ = GnuPGKeyFile.TryParse(good.AsMemory(0, len), out _, out _);
        }

        var limits = new GnuPGLimits { MaxS2kCount = 1 << 20 };
        for (int i = 0; i < good.Length; i++)
        {
            byte[] m = (byte[])good.Clone();
            m[i] ^= 0x21;
            if (GnuPGKeyFile.TryParse(m, out GnuPGKeyFile? kf, out _))
            {
                try
                {
                    using GnuPGSecretKey s = kf!.Unlock(Passphrase, limits);
                }
                catch (Exception e) when (e is GnuPGFormatException or GnuPGWrongPassphraseException or KdfLimitExceededException or NotSupportedException)
                {
                }
            }
        }
    }
}

/// <summary>Shows that an unlocked key is the private half of the OpenPGP public key GnuPG's keybox holds for it.</summary>
internal static class KeyProofs
{
    public static void Check(GnuPGSecretKey secret, GnuPGKeyFile kf, KeyPacket pub)
    {
        byte[] data = RandomNumberGenerator.GetBytes(100);
        switch (kf.Algorithm)
        {
            case "rsa":
            {
                using IRsaKey key = (IRsaKey)secret.ToSigningKey();
                using var rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters { Modulus = Trim(pub.Material.Values[0].Span), Exponent = Trim(pub.Material.Values[1].Span) });
                PublicKeyInfo info = PublicKeyInfo.FromAsymmetricAlgorithm(rsa);
                SignatureSpec spec = SignatureSpec.DefaultFor(info);
                Assert.Equal(SignatureStatus.Valid, spec.Verify(info, data, key.Sign(data, spec)).Status);

                // Decryption: encrypt to the OpenPGP public key, decrypt with the unlocked key.
                byte[] ct = rsa.Encrypt(data[..32], RSAEncryptionPadding.Pkcs1);
                Assert.Equal(data[..32], key.Decrypt(ct, DecryptionSpec.RsaPkcs1()));
                break;
            }

            case "ecc":
                CheckEcc(secret, kf, pub, data);
                break;
            default:
                throw new InvalidOperationException(kf.Algorithm);
        }
    }

    private static void CheckEcc(GnuPGSecretKey secret, GnuPGKeyFile kf, KeyPacket pub, byte[] data)
    {
        ReadOnlySpan<byte> point = pub.Material.Values[0].Span;
        switch (kf.Curve)
        {
            case "Ed25519":
            {
                using ISigningKey key = secret.ToSigningKey();
                PublicKeyInfo info = Spki([0x2b, 0x65, 0x70], point[1..]);
                SignatureSpec spec = SignatureSpec.Ed25519();
                Assert.Equal(SignatureStatus.Valid, spec.Verify(info, data, key.Sign(data, spec)).Status);
                break;
            }

            case "Ed448":
            {
                using ISigningKey key = secret.ToSigningKey();
                PublicKeyInfo info = Spki([0x2b, 0x65, 0x71], point);
                SignatureSpec spec = SignatureSpec.Ed448();
                Assert.Equal(SignatureStatus.Valid, spec.Verify(info, data, key.Sign(data, spec)).Status);
                break;
            }

            case "Cv25519" or "Curve25519":
            {
                using IAgreementKey key = secret.ToAgreementKey();
                using X25519PrivateKey peer = X25519PrivateKey.Generate();
                using IAgreementKey peerKey = PrivateKey.FromX25519(peer, ownsKey: false);
                PublicKeyInfo theirs = Spki([0x2b, 0x65, 0x6e], point[1..]);
                Assert.Equal(peerKey.Agree(theirs), key.Agree(peerKey.PublicKey));
                break;
            }

            case "X448" or "Cv448":
            {
                using IAgreementKey key = secret.ToAgreementKey();
                using X448PrivateKey peer = X448PrivateKey.Generate();
                using IAgreementKey peerKey = PrivateKey.FromX448(peer, ownsKey: false);
                PublicKeyInfo theirs = Spki([0x2b, 0x65, 0x6f], point.Length == 57 ? point[1..] : point);
                Assert.Equal(peerKey.Agree(theirs), key.Agree(peerKey.PublicKey));
                break;
            }

            default:
            {
                // NIST and Brainpool curves: the key works both as a signing key (ECDSA) and as an agreement key (ECDH).
                ECCurve curve = CurveOf(kf.Curve!);
                int size = (point.Length - 1) / 2;
                var prm = new ECParameters { Curve = curve, Q = new ECPoint { X = point.Slice(1, size).ToArray(), Y = point.Slice(1 + size, size).ToArray() } };
                using var ecdsa = ECDsa.Create(prm);
                PublicKeyInfo info = PublicKeyInfo.FromAsymmetricAlgorithm(ecdsa);
                using ISigningKey sk = secret.ToSigningKey();
                SignatureSpec spec = SignatureSpec.DefaultFor(info);
                Assert.Equal(SignatureStatus.Valid, spec.Verify(info, data, sk.Sign(data, spec)).Status);

                using IAgreementKey ak = secret.ToAgreementKey();
                using var peer = ECDiffieHellman.Create(curve);
                using IAgreementKey peerKey = PrivateKey.FromECDiffieHellman(peer, ownsKey: false);
                using var ours = ECDiffieHellman.Create(prm);
                Assert.Equal(peerKey.Agree(PublicKeyInfo.FromAsymmetricAlgorithm(ours)), ak.Agree(peerKey.PublicKey));
                break;
            }
        }
    }

    private static ECCurve CurveOf(string name) => name.Replace(" ", string.Empty, StringComparison.Ordinal).Replace("-", string.Empty, StringComparison.Ordinal).ToUpperInvariant() switch
    {
        "NISTP256" => ECCurve.NamedCurves.nistP256,
        "NISTP384" => ECCurve.NamedCurves.nistP384,
        "NISTP521" => ECCurve.NamedCurves.nistP521,
        "BRAINPOOLP256R1" => ECCurve.NamedCurves.brainpoolP256r1,
        "BRAINPOOLP384R1" => ECCurve.NamedCurves.brainpoolP384r1,
        "BRAINPOOLP512R1" => ECCurve.NamedCurves.brainpoolP512r1,
        _ => throw new InvalidOperationException(name),
    };

    private static byte[] Trim(ReadOnlySpan<byte> v)
    {
        while (v.Length > 0 && v[0] == 0)
        {
            v = v[1..];
        }

        return v.ToArray();
    }

    // RFC 8410 §4: AlgorithmIdentifier with the curve's OID and no parameters, then the raw key as a BIT STRING.
    private static PublicKeyInfo Spki(byte[] oidBody, ReadOnlySpan<byte> key)
    {
        var ms = new MemoryStream();
        // The algorithm identifier is SEQUENCE { OID }.
        byte[] alg = [0x30, (byte)(2 + oidBody.Length), 0x06, (byte)oidBody.Length, .. oidBody];
        byte[] bits = [0x03, (byte)(key.Length + 1), 0x00, .. key];
        int bodyLength = alg.Length + bits.Length;
        ms.WriteByte(0x30);
        ms.WriteByte((byte)bodyLength);
        ms.Write(alg);
        ms.Write(bits);
        return PublicKeyInfo.Parse(ms.ToArray());
    }
}
