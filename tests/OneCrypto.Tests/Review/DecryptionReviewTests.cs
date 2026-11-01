using System.Diagnostics;
using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace OneCrypto.Tests.Review;

/// <summary>
/// Findings of the decryption-path review for CMS (docs/decryption-review.md). A test marked <c>Skip = "review finding Dn"</c> fails today and
/// passes when the finding is fixed; the other tests pin behaviour the review found correct.
/// </summary>
public class DecryptionReviewTests
{
    private static readonly byte[] Kek = RandomNumberGenerator.GetBytes(32);

    private static CmsRecipient KekRecipient() => CmsRecipient.KeyEncryptionKey(Kek, "review"u8);

    private static CmsDecryptionKey KekKey() => CmsDecryptionKey.FromKeyEncryptionKey(Kek, "review"u8);

    private static byte[] Content(int n)
    {
        byte[] b = new byte[n];
        new Random(33).NextBytes(b);
        return b;
    }

    /// <summary>The message with one octet of the encrypted content changed.</summary>
    private static EnvelopedData Flip(EnvelopedData ed, int contentIndex)
    {
        byte[] enc = ed.Encoded.ToArray();
        int at = enc.AsSpan().IndexOf(ed.EncryptedContent.Span);
        Assert.True(at >= 0);
        enc[at + contentIndex] ^= 0x01;
        return EnvelopedData.Parse(enc);
    }

    private static long MedianTicks(Action a, int n)
    {
        var t = new long[n];
        for (int i = 0; i < n; i++)
        {
            long s = Stopwatch.GetTimestamp();
            a();
            t[i] = Stopwatch.GetTimestamp() - s;
        }

        Array.Sort(t);
        return t[n / 2];
    }

    // ---- D12: CBC padding failure is a timing oracle (the platform raises an exception only on the bad-padding path) ----

    [Fact(Skip = "review finding D12")]
    public void CbcBadPaddingTakesAsLongAsGoodPadding()
    {
        EnvelopedData ed = EnvelopedData.Create(Content(48), [KekRecipient()]); // 4 blocks including a full padding block
        int len = ed.EncryptedContent.Length;
        EnvelopedData badPad = Flip(ed, len - 32 + 15); // last byte of the second-to-last block: the padding block's last octet changes
        EnvelopedData goodPad = Flip(ed, 0);            // first block: the padding stays valid
        using CmsDecryptionKey key = KekKey();
        long bad = MedianTicks(() => Assert.Throws<CmsParseException>(() => badPad.Decrypt(key)), 2000);
        long good = MedianTicks(() => goodPad.Decrypt(key), 2000);
        Assert.True((double)bad / good < 1.5, $"bad-padding path {bad} ticks, good-padding path {good} ticks (median)");
    }

    // ---- D11: AuthEnvelopedData accepts authentication tags of 4 to 11 octets ----

    [Fact(Skip = "review finding D11")]
    public void AuthEnvelopedDataRefusesTagsShorterThanTwelveOctets()
    {
        // A four-octet CCM tag is a 2^-32 forgery per attempt. RFC 5084 §3.3 allows it; a library default should not.
        byte[] plain = Content(100);
        AuthEnvelopedData made = AuthEnvelopedData.Create(plain, [KekRecipient()], new CmsEncryptOptions { ContentEncryption = CmsOids.Aes256Ccm });
        byte[]? cek = CmsCiphers.AesUnwrap(Kek, ((KekRecipientInfo)made.RecipientInfos[0]).EncryptedKey.Span);
        Assert.NotNull(cek);
        CmsCiphers.TryGet(CmsOids.Aes256Ccm, out ContentCipher cipher);
        byte[] nonce = RandomNumberGenerator.GetBytes(13);
        byte[] ct = CmsCiphers.EncryptAead(cipher, cek, nonce, 4, plain, [], out byte[] tag);
        byte[] eci = EncryptedContentInfoData.Encode(CmsOids.Data, CmsCiphers.Describe(cipher, nonce, 4), ct);
        byte[] body = DerWriter.Sequence(DerWriter.SignedInteger(0), DerWriter.Set(made.RecipientInfos[0].Encoded.ToArray()), eci, DerWriter.OctetString(tag));
        AuthEnvelopedData shortTag = AuthEnvelopedData.Parse(ContentTypeReader.Wrap(CmsOids.AuthEnvelopedData, body));
        using CmsDecryptionKey key = KekKey();
        Assert.Throws<CmsParseException>(() => shortTag.Decrypt(key));
    }

    // ---- D13: many password recipients multiply the PBKDF2 work ----

    [Fact(Skip = "review finding D13")]
    public void PasswordRecipientsShareOneKeyDerivationBudget()
    {
        // Every PasswordRecipientInfo costs up to MaxPbkdf2Iterations (10 million) derivations, and up to 1024 of them are allowed.
        var recipients = new List<CmsRecipient>();
        for (int i = 0; i < 8; i++)
        {
            recipients.Add(CmsRecipient.Password("recipient-" + i, 400_000));
        }

        EnvelopedData ed = EnvelopedData.Create(Content(64), recipients);
        using CmsDecryptionKey wrong = CmsDecryptionKey.FromPassword("not any of them");
        var sw = Stopwatch.StartNew();
        Assert.ThrowsAny<CmsParseException>(() => ed.Decrypt(wrong));
        long all = sw.ElapsedMilliseconds;
        sw.Restart();
        _ = Rfc2898DeriveBytes.Pbkdf2("x", new byte[16], 400_000, HashAlgorithmName.SHA256, 32);
        long one = sw.ElapsedMilliseconds;
        Assert.True(all < 3 * Math.Max(one, 1), $"{all} ms for 8 recipients, {one} ms for one derivation");
    }

    // ---- D8: a truncated zlib stream in CompressedData ----

    [Fact(Skip = "review finding D8")]
    public void ATruncatedCompressedDataStreamIsAnError()
    {
        byte[] plain = Content(20_000);
        CompressedData cd = CompressedData.Create(plain);
        byte[] enc = cd.Encoded.ToArray();
        ReadOnlySpan<byte> z = cd.CompressedContent.Span;
        int at = enc.AsSpan().IndexOf(z);
        Assert.True(at >= 0);
        // Cut the stream in the middle (and drop the checksum); the enclosing lengths are rebuilt so the damage is only in the zlib data.
        byte[] cut = z[..(z.Length / 2)].ToArray();
        byte[] body = DerWriter.Sequence(DerWriter.SignedInteger(0), AlgorithmIdentifier.Create(CmsOids.ZlibCompress).Encoded.ToArray(), EncapsulatedContent.Encode(CmsOids.Data, cut));
        CompressedData truncated = CompressedData.Parse(ContentTypeReader.Wrap(CmsOids.CompressedData, body));
        Assert.Throws<CmsParseException>(() => truncated.Decompress());
    }

    // ---- by design, pinned: CBC is unauthenticated and the one-shot call says nothing about it (D10 is docs/report) ----

    [Fact]
    public void CbcWithValidPaddingDecryptsTamperedDataUnderStandardAndFailsUnderStrict()
    {
        byte[] plain = Content(48);
        EnvelopedData ed = EnvelopedData.Create(plain, [KekRecipient()]);
        EnvelopedData tampered = Flip(ed, 0);
        using CmsDecryptionKey key = KekKey();
        var standard = new CmsDecryptOptions { Policy = CryptoPolicy.Standard, ReferenceTime = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero) };
        byte[] got = tampered.Decrypt(key, standard); // accepted: a flagged decision is not an error and is not reported to the caller
        Assert.NotEqual(plain, got);
        Assert.Equal(plain.Length, got.Length);
        var strict = new CmsDecryptOptions { Policy = CryptoPolicy.Strict, ReferenceTime = standard.ReferenceTime };
        Assert.ThrowsAny<PolicyViolationException>(() => tampered.Decrypt(key, strict));
    }

    // ---- checked and correct ----

    [Fact]
    public void AuthEnvelopedDataFailsClosedOnEveryTamperingAndGivesOneError()
    {
        byte[] plain = Content(300);
        AuthEnvelopedData made = AuthEnvelopedData.Create(plain, [KekRecipient()], new CmsEncryptOptions { AuthenticatedAttributes = [CmsAttributeEntry.Create("1.2.840.113549.1.9.3", DerWriter.Oid(CmsOids.Data))] });
        using CmsDecryptionKey key = KekKey();
        Assert.Equal(plain, made.Decrypt(key));
        byte[] enc = made.Encoded.ToArray();
        ReadOnlySpan<byte> ct = made.EncryptedContent.Span;
        ReadOnlySpan<byte> tag = made.MessageAuthenticationCode.Span;
        int ctAt = enc.AsSpan().IndexOf(ct);
        int tagAt = enc.AsSpan().LastIndexOf(tag);
        foreach (int at in new[] { ctAt, ctAt + ct.Length - 1, tagAt, tagAt + tag.Length - 1 })
        {
            byte[] bad = (byte[])enc.Clone();
            bad[at] ^= 0x80;
            var e = Assert.Throws<CmsParseException>(() => AuthEnvelopedData.Parse(bad).Decrypt(key));
            Assert.Equal(CmsError.DecryptionFailed, e.Error);
        }

        // the streaming twin releases nothing either
        byte[] flipped = (byte[])enc.Clone();
        flipped[ctAt + 5] ^= 1;
        using var sink = new MemoryStream();
        Assert.Throws<CmsParseException>(() => AuthEnvelopedData.DecryptStream(new MemoryStream(flipped), sink, key));
        Assert.Equal(0, sink.Length);
    }

    [Fact]
    public void RsaPkcs1FailuresAreIndistinguishableByErrorFromBadPadding()
    {
        // RFC 3218 §2.3: a damaged key transport, a key of the wrong length and bad CBC padding end in the same exception type, code and text.
        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        EnvelopedData ed = EnvelopedData.Create(Content(64), [CmsRecipient.KeyTransport(kit.Certificate, KeyTransportScheme.Pkcs1V15)], new CmsEncryptOptions { AllowLegacy = true });
        using CmsDecryptionKey key = kit.Key();
        var results = new List<CmsParseException>();

        byte[] enc = ed.Encoded.ToArray();
        byte[] wrapped = ((KeyTransRecipientInfo)ed.RecipientInfos[0]).EncryptedKey.ToArray();
        int at = enc.AsSpan().IndexOf(wrapped);
        enc[at + 7] ^= 0x10;
        results.Add(Assert.Throws<CmsParseException>(() => EnvelopedData.Parse(enc).Decrypt(key)));

        results.Add(Assert.Throws<CmsParseException>(() => Flip(ed, ed.EncryptedContent.Length - 17).Decrypt(key)));
        Assert.All(results, r => Assert.Equal(CmsError.DecryptionFailed, r.Error));
        Assert.Single(results.Select(static r => r.Message).Distinct());
    }

    [Fact]
    public void CbcStreamingDecryptReleasesEarlierBlocksBeforeThePaddingIsKnown()
    {
        // Documented behaviour (docs/cms.md): the caller must discard what was written when the call throws.
        EnvelopedData ed = EnvelopedData.Create(Content(4096), [KekRecipient()]);
        EnvelopedData bad = Flip(ed, ed.EncryptedContent.Length - 17);
        using CmsDecryptionKey key = KekKey();
        using var sink = new MemoryStream();
        Assert.Throws<CmsParseException>(() => EnvelopedData.DecryptStream(new MemoryStream(bad.Encoded.ToArray()), sink, key));
        Assert.True(sink.Length > 0, "earlier blocks were passed on before the failure");
    }

    [Fact]
    public void RecipientsThatCannotBeReadDoNotMaskAGoodOne()
    {
        // A key-encryption-key recipient with a damaged wrap sits before the good one: the loop tries each recipient on its own.
        byte[] plain = Content(50);
        byte[] otherKek = RandomNumberGenerator.GetBytes(32);
        EnvelopedData ed = EnvelopedData.Create(plain, [CmsRecipient.KeyEncryptionKey(otherKek, "review"u8), KekRecipient()]);
        using CmsDecryptionKey key = KekKey();
        Assert.Equal(plain, ed.Decrypt(key));
    }

    [Fact]
    public void CompressedDataBombsAreRefusedWithATypedError()
    {
        byte[] zeros = new byte[64 << 20];
        CompressedData cd = CompressedData.Create(zeros);
        var e = Assert.Throws<CmsParseException>(() => cd.Decompress(new CmsLimits { MaxDecompressedBytes = 8 << 20 }));
        Assert.Equal(CmsError.LimitExceeded, e.Error);
    }
}
