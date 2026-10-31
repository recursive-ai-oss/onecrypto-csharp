using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace OneCrypto.Fuzz;

/// <summary>
/// The encrypted and simple CMS content types. The first byte picks the content type (modulo 7: EnvelopedData, AuthEnvelopedData,
/// AuthenticatedData, EncryptedData, DigestedData, CompressedData, streamed EnvelopedData); the rest is the ContentInfo. Each is parsed
/// and then opened with fixed keys. Only the library's typed exceptions may escape the one-shot calls, and decryption must either
/// succeed or raise <see cref="CmsParseException"/>.
/// </summary>
internal static class CmsEnvelopedTarget
{
    private static readonly byte[] Kek = new byte[32];

    private static readonly byte[] Plain = RandomNumberGenerator.GetBytes(300);

    private static readonly CmsLimits Small = new() { MaxContentBytes = 1 << 20, MaxDecompressedBytes = 1 << 20, MaxPbkdf2Iterations = 2000 };

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
        {
            return;
        }

        byte[] rest = data[1..].ToArray();
        var options = new CmsDecryptOptions { Limits = Small, AllowLegacyCiphers = true };
        using CmsDecryptionKey rsa = RecipientKit.Get(RecipKind.Rsa).Key();
        using CmsDecryptionKey kek = CmsDecryptionKey.FromKeyEncryptionKey(Kek, "id"u8);
        using CmsDecryptionKey pw = CmsDecryptionKey.FromPassword("p");
        switch (data[0] % 7)
        {
            case 0:
                if (EnvelopedData.TryParse(rest, out EnvelopedData? ed, Small) && ed is not null)
                {
                    foreach (CmsDecryptionKey k in (CmsDecryptionKey[])[rsa, kek, pw])
                    {
                        Try(() => ed.Decrypt(k, options));
                    }
                }

                break;
            case 1:
                if (AuthEnvelopedData.TryParse(rest, out AuthEnvelopedData? ae, Small) && ae is not null)
                {
                    foreach (CmsDecryptionKey k in (CmsDecryptionKey[])[rsa, kek, pw])
                    {
                        Try(() => ae.Decrypt(k, options));
                    }
                }

                break;
            case 2:
                if (AuthenticatedData.TryParse(rest, out AuthenticatedData? ad, Small) && ad is not null)
                {
                    foreach (CmsDecryptionKey k in (CmsDecryptionKey[])[rsa, kek, pw])
                    {
                        _ = ad.Verify(k, Plain, options).IsValid;
                    }
                }

                break;
            case 3:
                if (EncryptedData.TryParse(rest, out EncryptedData? enc, Small) && enc is not null)
                {
                    Try(() => enc.Decrypt(Kek, options));
                }

                break;
            case 4:
                if (DigestedData.TryParse(rest, out DigestedData? dd, Small) && dd is not null)
                {
                    _ = dd.Verify(Plain).IsValid;
                }

                break;
            case 5:
                if (CompressedData.TryParse(rest, out CompressedData? cd, Small) && cd is not null)
                {
                    Try(() => cd.Decompress(Small));
                }

                break;
            default:
                Try(() => EnvelopedData.DecryptStream(new MemoryStream(rest), Stream.Null, rsa, options));
                Try(() => EnvelopedData.DecryptStream(new MemoryStream(rest), Stream.Null, kek, options));
                Try(() => _ = SignedData.VerifyStream(new MemoryStream(rest), Stream.Null, null, Small));

                // The asynchronous twins must end the same way, and release the same plaintext, as the synchronous forms.
                var syncOut = new MemoryStream();
                bool syncOk = Succeeds(() => EnvelopedData.DecryptStream(new MemoryStream(rest), syncOut, rsa, options));
                var asyncOut = new MemoryStream();
                bool asyncOk = Succeeds(() => EnvelopedData.DecryptStreamAsync(new MemoryStream(rest), asyncOut, rsa, options).GetAwaiter().GetResult());
                if (syncOk != asyncOk || (syncOk && !syncOut.ToArray().AsSpan().SequenceEqual(asyncOut.ToArray())))
                {
                    throw new InvalidOperationException("DecryptStream and DecryptStreamAsync disagree");
                }

                var syncAuth = new MemoryStream();
                bool authOk = Succeeds(() => AuthEnvelopedData.DecryptStream(new MemoryStream(rest), syncAuth, rsa, options));
                var asyncAuth = new MemoryStream();
                bool authAsyncOk = Succeeds(() => AuthEnvelopedData.DecryptStreamAsync(new MemoryStream(rest), asyncAuth, rsa, options).GetAwaiter().GetResult());
                if (authOk != authAsyncOk || (authOk && !syncAuth.ToArray().AsSpan().SequenceEqual(asyncAuth.ToArray())))
                {
                    throw new InvalidOperationException("AuthEnvelopedData.DecryptStream and its async twin disagree");
                }

                break;
        }
    }

    private static bool Succeeds(Action a)
    {
        try
        {
            a();
            return true;
        }
        catch (CmsParseException)
        {
            return false;
        }
    }

    private static void Try(Action a)
    {
        try
        {
            a();
        }
        catch (CmsParseException)
        {
        }
    }

    /// <summary>Starting inputs: one message of each content type, in several recipient forms.</summary>
    public static IEnumerable<byte[]> Seeds()
    {
        RecipientKit rsa = RecipientKit.Get(RecipKind.Rsa);
        RecipientKit ec = RecipientKit.Get(RecipKind.P256);
        RecipientKit x = RecipientKit.Get(RecipKind.X25519);
        yield return [0, .. EnvelopedData.Create(Plain, [CmsRecipient.KeyTransport(rsa.Certificate)]).Encoded.ToArray()];
        yield return [0, .. EnvelopedData.Create(Plain, [CmsRecipient.KeyAgreement(ec.Certificate), CmsRecipient.KeyAgreement(x.Certificate)]).Encoded.ToArray()];
        yield return [0, .. EnvelopedData.Create(Plain, [CmsRecipient.KeyEncryptionKey(Kek, "id"u8), CmsRecipient.Password("p", 1000)]).Encoded.ToArray()];
        yield return [1, .. AuthEnvelopedData.Create(Plain, [CmsRecipient.KeyTransport(rsa.Certificate)]).Encoded.ToArray()];
        yield return [2, .. AuthenticatedData.Create(Plain, [CmsRecipient.KeyEncryptionKey(Kek, "id"u8)], new AuthenticatedDataOptions { Detached = true }).Encoded.ToArray()];
        yield return [3, .. EncryptedData.Create(Plain, Kek).Encoded.ToArray()];
        yield return [4, .. DigestedData.Create(Plain).Encoded.ToArray()];
        yield return [5, .. CompressedData.Create(Plain).Encoded.ToArray()];
        var ms = new MemoryStream();
        EnvelopedData.EncryptStream(new MemoryStream(Plain), ms, [CmsRecipient.KeyEncryptionKey(Kek, "id"u8)]);
        yield return [6, .. ms.ToArray()];
        var sg = new MemoryStream();
        SignedData.SignStream(new MemoryStream(Plain), sg, [CmsKeys.Get(SigKind.P256).Spec()]);
        yield return [6, .. sg.ToArray()];
    }
}
