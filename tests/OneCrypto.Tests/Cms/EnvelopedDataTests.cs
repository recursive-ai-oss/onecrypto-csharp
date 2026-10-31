using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace OneCrypto.Tests.Cms;

/// <summary>EnvelopedData, AuthEnvelopedData and the simple content types: every recipient kind, every cipher, damaged inputs.</summary>
public class EnvelopedDataTests
{
    private static readonly byte[] Content = RandomNumberGenerator.GetBytes(1000);

    private static CmsRecipient Recipient(RecipKind k, RecipientKit kit) => k switch
    {
        RecipKind.Rsa => CmsRecipient.KeyTransport(kit.Certificate),
        RecipKind.MlKem768 => CmsRecipient.Kem(kit.Certificate),
        _ => CmsRecipient.KeyAgreement(kit.Certificate),
    };

    public static IEnumerable<object[]> Kinds() => Enum.GetValues<RecipKind>().Select(static k => new object[] { k });

    [Theory]
    [MemberData(nameof(Kinds))]
    public void EnvelopedRoundTrips(RecipKind kind)
    {
        Assert.SkipUnless(RecipientKit.IsAvailable(kind), "unavailable here");
        RecipientKit kit = RecipientKit.Get(kind);
        foreach (string alg in new[] { Cms128, Cms256 })
        {
            EnvelopedData made = EnvelopedData.Create(Content, [Recipient(kind, kit)], new CmsEncryptOptions { ContentEncryption = alg });
            EnvelopedData ed = EnvelopedData.Parse(made.Encoded);
            using CmsDecryptionKey key = kit.Key();
            Assert.Equal(Content, ed.Decrypt(key));
        }
    }

    private const string Cms128 = CmsOids.Aes128Cbc;
    private const string Cms256 = CmsOids.Aes256Cbc;

    [Theory]
    [MemberData(nameof(Kinds))]
    public void AuthEnvelopedRoundTrips(RecipKind kind)
    {
        Assert.SkipUnless(RecipientKit.IsAvailable(kind), "unavailable here");
        RecipientKit kit = RecipientKit.Get(kind);
        foreach (string alg in new[] { CmsOids.Aes128Gcm, CmsOids.Aes256Gcm, CmsOids.Aes256Ccm })
        {
            AuthEnvelopedData made = AuthEnvelopedData.Create(Content, [Recipient(kind, kit)], new CmsEncryptOptions { ContentEncryption = alg });
            using CmsDecryptionKey key = kit.Key();
            Assert.Equal(Content, AuthEnvelopedData.Parse(made.Encoded).Decrypt(key));
        }
    }

    [Fact]
    public void Pkcs1V15NeedsOptInToWriteAndRoundTrips()
    {
        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        CmsRecipient legacy = CmsRecipient.KeyTransport(kit.Certificate, KeyTransportScheme.Pkcs1V15);
        Assert.Throws<NotSupportedException>(() => EnvelopedData.Create(Content, [legacy]));
        EnvelopedData made = EnvelopedData.Create(Content, [legacy], new CmsEncryptOptions { AllowLegacy = true });
        using CmsDecryptionKey key = kit.Key();
        Assert.Equal(Content, made.Decrypt(key));
        var refuse = new CmsDecryptOptions { AllowPkcs1V15KeyTransport = false };
        Assert.Equal(CmsError.NoMatchingRecipient, Assert.Throws<CmsParseException>(() => made.Decrypt(key, refuse)).Error);
    }

    [Fact]
    public void OaepHashesRoundTrip()
    {
        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        using CmsDecryptionKey key = kit.Key();
        foreach (KeyTransportScheme s in new[] { KeyTransportScheme.OaepSha1, KeyTransportScheme.OaepSha256, KeyTransportScheme.OaepSha384, KeyTransportScheme.OaepSha512 })
        {
            Assert.Equal(Content, EnvelopedData.Create(Content, [CmsRecipient.KeyTransport(kit.Certificate, s)]).Decrypt(key));
        }
    }

    [Fact]
    public void SeveralRecipientsEachOpenTheMessage()
    {
        var kinds = new[] { RecipKind.Rsa, RecipKind.P256, RecipKind.X25519, RecipKind.X448 };
        var kek = RandomNumberGenerator.GetBytes(32);
        var recipients = kinds.Select(static k => Recipient(k, RecipientKit.Get(k))).Append(CmsRecipient.KeyEncryptionKey(kek, "kek-1"u8)).Append(CmsRecipient.Password("correct horse", 1000)).ToList();
        EnvelopedData ed = EnvelopedData.Parse(EnvelopedData.Create(Content, recipients).Encoded);
        Assert.Equal(6, ed.RecipientInfos.Count);
        Assert.Equal(3, ed.Version); // RFC 5652 §6.1: a password recipient makes it version 3.
        foreach (RecipKind k in kinds)
        {
            using CmsDecryptionKey key = RecipientKit.Get(k).Key();
            Assert.Equal(Content, ed.Decrypt(key));
        }

        using (CmsDecryptionKey key = CmsDecryptionKey.FromKeyEncryptionKey(kek, "kek-1"u8))
        {
            Assert.Equal(Content, ed.Decrypt(key));
        }

        using (CmsDecryptionKey key = CmsDecryptionKey.FromPassword("correct horse"))
        {
            Assert.Equal(Content, ed.Decrypt(key));
        }
    }

    [Theory]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    public void KeyEncryptionKeysWrapWithAndWithoutPadding(int size)
    {
        byte[] kek = RandomNumberGenerator.GetBytes(size);
        foreach (bool padded in new[] { false, true })
        {
            EnvelopedData ed = EnvelopedData.Parse(EnvelopedData.Create(Content, [CmsRecipient.KeyEncryptionKey(kek, "id"u8, padded)]).Encoded);
            var ri = (KekRecipientInfo)ed.RecipientInfos[0];
            Assert.Equal(padded, ri.KeyEncryptionAlgorithm.Oid.StartsWith("2.16.840.1.101.3.4.1", StringComparison.Ordinal) && ri.KeyEncryptionAlgorithm.Oid is CmsOids.Aes128WrapPad or CmsOids.Aes192WrapPad or CmsOids.Aes256WrapPad);
            using CmsDecryptionKey key = CmsDecryptionKey.FromKeyEncryptionKey(kek, "id"u8);
            Assert.Equal(Content, ed.Decrypt(key));
        }
    }

    [Fact]
    public void WrongKeysAreRefusedTheSameWay()
    {
        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        EnvelopedData ed = EnvelopedData.Create(Content, [CmsRecipient.KeyTransport(kit.Certificate)]);
        using CmsDecryptionKey other = CmsDecryptionKey.FromRsa(RSA.Create(2048));
        CmsParseException e = Assert.Throws<CmsParseException>(() => ed.Decrypt(other));
        Assert.Equal(CmsError.DecryptionFailed, e.Error);
        using CmsDecryptionKey wrongPassword = CmsDecryptionKey.FromPassword("x");
        EnvelopedData pw = EnvelopedData.Create(Content, [CmsRecipient.Password("right", 1000)]);
        Assert.Equal(CmsError.DecryptionFailed, Assert.Throws<CmsParseException>(() => pw.Decrypt(wrongPassword)).Error);
    }

    [Fact]
    public void Pkcs1V15FailuresLookTheSameWhateverWentWrong()
    {
        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        EnvelopedData made = EnvelopedData.Create(Content, [CmsRecipient.KeyTransport(kit.Certificate, KeyTransportScheme.Pkcs1V15)], new CmsEncryptOptions { AllowLegacy = true });
        using CmsDecryptionKey key = kit.Key();
        var ki = (KeyTransRecipientInfo)made.RecipientInfos[0];
        byte[] enc = made.Encoded.ToArray();
        int keyAt = enc.AsSpan().IndexOf(ki.EncryptedKey.Span);
        int ctAt = enc.AsSpan().IndexOf(made.EncryptedContent.Span);
        var results = new List<(CmsError, string, Type)>();
        int passed = 0;
        foreach (int at in new[] { keyAt, keyAt + 100, keyAt + 255, ctAt + made.EncryptedContent.Length - 1, ctAt + made.EncryptedContent.Length - 2 })
        {
            foreach (byte flip in new byte[] { 0x10, 0x21, 0x42 })
            {
                byte[] bad = (byte[])enc.Clone();
                bad[at] ^= flip;
                try
                {
                    EnvelopedData.Parse(bad).Decrypt(key);
                    passed++; // a damaged last block has valid padding once in 256 tries; CBC cannot tell.
                }
                catch (CmsParseException e)
                {
                    results.Add((e.Error, e.Message, e.GetType()));
                }
            }
        }

        Assert.True(passed <= 1, $"{passed} damaged messages decrypted");
        Assert.Single(results.Distinct());
        Assert.Equal(CmsError.DecryptionFailed, results[0].Item1);
    }

    [Fact]
    public void EveryRegionOfAnEnvelopedMessageFailsClosed()
    {
        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        EnvelopedData made = EnvelopedData.Create(Content.AsSpan(0, 96), [CmsRecipient.KeyTransport(kit.Certificate)]);
        using CmsDecryptionKey key = kit.Key();
        byte[] enc = made.Encoded.ToArray();
        var ki = (KeyTransRecipientInfo)made.RecipientInfos[0];
        int keyAt = enc.AsSpan().IndexOf(ki.EncryptedKey.Span);
        int ctAt = enc.AsSpan().IndexOf(made.EncryptedContent.Span);
        int released = 0;
        for (int i = 0; i < ki.EncryptedKey.Length; i++)
        {
            byte[] bad = (byte[])enc.Clone();
            bad[keyAt + i] ^= 0x01;
            Assert.Throws<CmsParseException>(() => EnvelopedData.Parse(bad).Decrypt(key));
        }

        for (int i = 0; i < made.EncryptedContent.Length; i++)
        {
            byte[] bad = (byte[])enc.Clone();
            bad[ctAt + i] ^= 0x01;
            try
            {
                // CBC cannot notice a change that leaves valid padding; the plaintext then differs from the original.
                byte[] pt = EnvelopedData.Parse(bad).Decrypt(key);
                released++;
                Assert.NotEqual(Content.AsSpan(0, 96).ToArray(), pt);
            }
            catch (CmsParseException)
            {
            }
        }

        // Only the last block carries the padding: changes before it pass, changes inside it are refused (up to the 1-in-256 chance).
        Assert.True(released >= 80 && released <= made.EncryptedContent.Length - 8, $"{released} flips passed");
    }

    [Fact]
    public void EveryByteOfAnAuthEnvelopedMessageIsProtected()
    {
        foreach (string alg in new[] { CmsOids.Aes256Gcm, CmsOids.Aes128Ccm })
        {
            RecipientKit kit = RecipientKit.Get(RecipKind.P256);
            var opts = new CmsEncryptOptions
            {
                ContentEncryption = alg,
                ContentType = CmsOids.EncryptedData, // not id-data, so a content-type attribute is authenticated
                AuthenticatedAttributes = [CmsAttributeEntry.Create("1.2.3.4.5", [0x0C, 0x01, 0x41])],
            };
            AuthEnvelopedData made = AuthEnvelopedData.Create(Content.AsSpan(0, 64), [CmsRecipient.KeyAgreement(kit.Certificate)], opts);
            using CmsDecryptionKey key = kit.Key();
            byte[] enc = made.Encoded.ToArray();
            ReadOnlySpan<byte> ct = made.EncryptedContent.Span;
            ReadOnlySpan<byte> tag = made.MessageAuthenticationCode.Span;
            int ctAt = enc.AsSpan().IndexOf(ct);
            int tagAt = enc.AsSpan().LastIndexOf(tag);
            var regions = new List<int>();
            regions.AddRange(Enumerable.Range(ctAt, ct.Length));
            regions.AddRange(Enumerable.Range(tagAt, tag.Length));
            int nonceAt = enc.AsSpan().IndexOf(made.ContentEncryptionAlgorithm.Parameters.Span.Slice(4, alg == CmsOids.Aes128Ccm ? 13 : 12));
            regions.AddRange(Enumerable.Range(nonceAt, alg == CmsOids.Aes128Ccm ? 13 : 12));
            int attrAt = enc.AsSpan().IndexOf(new byte[] { 0x0C, 0x01, 0x41 });
            regions.Add(attrAt + 2);
            foreach (int at in regions)
            {
                byte[] bad = (byte[])enc.Clone();
                bad[at] ^= 0x80;
                CmsParseException e = Assert.Throws<CmsParseException>(() => AuthEnvelopedData.Parse(bad).Decrypt(key));
                Assert.Equal(CmsError.DecryptionFailed, e.Error);
            }

            Assert.Equal(Content.AsSpan(0, 64).ToArray(), AuthEnvelopedData.Parse(enc).Decrypt(key));
        }
    }

    [Fact]
    public void WrappedKeysOfAuthEnvelopedFailClosed()
    {
        RecipientKit kit = RecipientKit.Get(RecipKind.X25519);
        AuthEnvelopedData made = AuthEnvelopedData.Create(Content, [CmsRecipient.KeyAgreement(kit.Certificate)]);
        using CmsDecryptionKey key = kit.Key();
        var ka = (KeyAgreeRecipientInfo)made.RecipientInfos[0];
        byte[] enc = made.Encoded.ToArray();
        int at = enc.AsSpan().IndexOf(ka.RecipientEncryptedKeys[0].EncryptedKey.Span);
        for (int i = 0; i < ka.RecipientEncryptedKeys[0].EncryptedKey.Length; i++)
        {
            byte[] bad = (byte[])enc.Clone();
            bad[at + i] ^= 1;
            Assert.Throws<CmsParseException>(() => AuthEnvelopedData.Parse(bad).Decrypt(key));
        }
    }

    [Fact]
    public void AuthEnvelopedRefusesAMissingContentTypeAttribute()
    {
        // RFC 5083 §2.1: any content type but id-data needs the authenticated attributes.
        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        AuthEnvelopedData made = AuthEnvelopedData.Create(Content, [CmsRecipient.KeyTransport(kit.Certificate)], new CmsEncryptOptions { ContentType = CmsOids.EncryptedData });
        Assert.NotNull(made.AuthenticatedAttributes);
        using CmsDecryptionKey key = kit.Key();
        Assert.Equal(Content, made.Decrypt(key));
    }

    [Fact]
    public void LargeCiphertextsAreRefusedBeyondTheLimit()
    {
        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        EnvelopedData made = EnvelopedData.Create(Content, [CmsRecipient.KeyTransport(kit.Certificate)]);
        using CmsDecryptionKey key = kit.Key();
        var tight = new CmsDecryptOptions { Limits = new CmsLimits { MaxContentBytes = 100 } };
        Assert.Equal(CmsError.UnexpectedStructure, Assert.Throws<CmsParseException>(() => made.Decrypt(key, tight)).Error);
        var many = new CmsLimits { MaxRecipients = 1 };
        EnvelopedData two = EnvelopedData.Create(Content, [CmsRecipient.KeyTransport(kit.Certificate), CmsRecipient.Password("p", 1000)]);
        Assert.Equal(CmsError.LimitExceeded, Assert.Throws<CmsParseException>(() => EnvelopedData.Parse(two.Encoded, many)).Error);
        Assert.False(EnvelopedData.TryParse(two.Encoded, out _, many));
    }

    [Fact]
    public void PasswordIterationCostBombsAreRefused()
    {
        EnvelopedData pw = EnvelopedData.Create(Content, [CmsRecipient.Password("p", 5000)]);
        using CmsDecryptionKey key = CmsDecryptionKey.FromPassword("p");
        var tight = new CmsDecryptOptions { Limits = new CmsLimits { MaxPbkdf2Iterations = 1000 } };
        Assert.Throws<CmsParseException>(() => pw.Decrypt(key, tight));
        Assert.Equal(Content, pw.Decrypt(key));
    }

    [Fact]
    public void TripleDesNeedsOptIn()
    {
        // Built by hand: 3DES-CBC content under a key-encryption key, as old messages are.
        byte[] cek = RandomNumberGenerator.GetBytes(24);
        byte[] iv = RandomNumberGenerator.GetBytes(8);
#pragma warning disable CA5350
        using var des = TripleDES.Create();
#pragma warning restore CA5350
        des.Key = cek;
        byte[] ct = des.EncryptCbc(Content, iv, PaddingMode.PKCS7);
        byte[] kek = RandomNumberGenerator.GetBytes(32);
        byte[] ed = EnvKit.WithKek(CmsOids.TripleDesCbc, iv, ct, kek, "id"u8.ToArray(), cek);
        EnvelopedData msg = EnvelopedData.Parse(ed);
        using CmsDecryptionKey key = CmsDecryptionKey.FromKeyEncryptionKey(kek, "id"u8);
        Assert.Throws<CmsParseException>(() => msg.Decrypt(key));
        Assert.Equal(Content, msg.Decrypt(key, new CmsDecryptOptions { AllowLegacyCiphers = true }));
    }

    [Fact]
    public void EncryptedDataRoundTripsAndFailsClosed()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        EncryptedData made = EncryptedData.Create(Content, key);
        Assert.Equal(Content, EncryptedData.Parse(made.Encoded).Decrypt(key));
        Assert.Equal(CmsError.DecryptionFailed, Assert.Throws<CmsParseException>(() => made.Decrypt(RandomNumberGenerator.GetBytes(32))).Error);
        EncryptedData withAttrs = EncryptedData.Create(Content, key, new CmsEncryptOptions { UnprotectedAttributes = [CmsAttributeEntry.Create("1.2.3.4", [0x05, 0x00])] });
        Assert.Equal(2, withAttrs.Version);
        Assert.Single(withAttrs.UnprotectedAttributes!);
    }

    [Fact]
    public void DigestedDataVerifies()
    {
        DigestedData made = DigestedData.Create(Content);
        DigestedData dd = DigestedData.Parse(made.Encoded);
        Assert.True(dd.Verify().IsValid);
        byte[] bad = made.Encoded.ToArray();
        bad[bad.AsSpan().IndexOf(Content.AsSpan(0, 16)) + 3] ^= 1;
        Assert.False(DigestedData.Parse(bad).Verify().IsValid);
        DigestedData detached = DigestedData.Parse(DigestedData.Create(Content, detached: true).Encoded);
        Assert.False(detached.Verify().IsValid);
        Assert.True(detached.Verify(Content).IsValid);
        Assert.Equal(2, DigestedData.Create(Content, CmsOids.EncryptedData).Version);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AuthenticatedDataVerifies(bool attrs)
    {
        RecipientKit kit = RecipientKit.Get(RecipKind.P384);
        AuthenticatedData made = AuthenticatedData.Create(Content, [CmsRecipient.KeyAgreement(kit.Certificate)], new AuthenticatedDataOptions { AuthenticatedAttributes = attrs });
        using CmsDecryptionKey key = kit.Key();
        AuthenticatedData ad = AuthenticatedData.Parse(made.Encoded);
        CmsIntegrityReport r = ad.Verify(key);
        Assert.True(r.IsValid, string.Join("; ", r.Checks.Select(static c => c.Rule + ":" + c.Status)));
        byte[] bad = made.Encoded.ToArray();
        bad[bad.AsSpan().IndexOf(Content.AsSpan(0, 16)) + 1] ^= 1;
        Assert.False(AuthenticatedData.Parse(bad).Verify(key).IsValid);
        byte[] badMac = made.Encoded.ToArray();
        badMac[^1] ^= 1;
        Assert.False(AuthenticatedData.Parse(badMac).Verify(key).IsValid);
        AuthenticatedData det = AuthenticatedData.Parse(AuthenticatedData.Create(Content, [CmsRecipient.KeyAgreement(kit.Certificate)], new AuthenticatedDataOptions { Detached = true, AuthenticatedAttributes = attrs }).Encoded);
        Assert.True(det.Verify(key, Content).IsValid);
        Assert.False(det.Verify(key).IsValid);
    }

    [Fact]
    public void CompressedDataRoundTripsAndStopsBombs()
    {
        byte[] data = new byte[200_000];
        CompressedData made = CompressedData.Create(data);
        CompressedData cd = CompressedData.Parse(made.Encoded);
        Assert.Equal(data, cd.Decompress(new CmsLimits { MaxDecompressionRatio = 100_000 }));
        CmsParseException e = Assert.Throws<CmsParseException>(() => cd.Decompress(new CmsLimits { MaxDecompressionRatio = 100 }));
        Assert.Equal(CmsError.LimitExceeded, e.Error);
        Assert.Equal(CmsError.LimitExceeded, Assert.Throws<CmsParseException>(() => cd.Decompress(new CmsLimits { MaxDecompressedBytes = 1000, MaxDecompressionRatio = 100_000 })).Error);
        byte[] text = RandomNumberGenerator.GetBytes(5000);
        Assert.Equal(text, CompressedData.Parse(CompressedData.Create(text).Encoded).Decompress());
    }
}

/// <summary>Builds an EnvelopedData by hand with a key-encryption-key recipient, for content algorithms we only read.</summary>
internal static class EnvKit
{
    public static byte[] WithKek(string contentOid, byte[] iv, byte[] ciphertext, byte[] kek, byte[] kekId, byte[] cek)
    {
        using var kw = new RecursiveAI.OneCrypto.Primitives.AesKeyWrap(kek);
        byte[] wrapped = new byte[cek.Length + 8];
        kw.Wrap(cek, wrapped);
        byte[] kekri = Der.Ctx(2, Der.Int(4), Der.Seq(Der.Oct(kekId)), Der.Seq(Der.Oid(CmsOids.Aes256Wrap)), Der.Oct(wrapped));
        byte[] eci = Der.Seq(Der.Oid(CmsOids.Data), Der.Seq(Der.Oid(contentOid), Der.Oct(iv)), Der.CtxPrim(0, ciphertext));
        byte[] body = Der.Seq(Der.Int(2), Der.Set(kekri), eci);
        return Der.Seq(Der.Oid(CmsOids.EnvelopedData), Der.Ctx(0, body));
    }
}
