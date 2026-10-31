using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RecursiveAI.OneCrypto.Cms;

namespace OneCrypto.Tests.Support;

/// <summary>Shared pieces for tests that sign and verify raw CMS: a content, digest callbacks, and an in-process time-stamp authority.</summary>
internal static class CmsFixture
{
    /// <summary>The bytes every test signature covers.</summary>
    public static readonly byte[] Content = "Hello signing world"u8.ToArray();

    public static Func<HashAlgorithmName, byte[]?> DigestOf(byte[] content) => name => CryptographicOperations.HashData(name, content);

    public static CmsVerifyOptions Trust => TestPki.Shared.Trusting();

    /// <summary>Verifies the first signer of <paramref name="cms"/> over <see cref="Content"/> (or the given bytes).</summary>
    public static CmsSignerResult VerifyOne(byte[] cms, CmsVerifyOptions? options = null, byte[]? content = null) =>
        CmsSignerVerifier.Verify(cms, DigestOf(content ?? Content), options ?? Trust, CancellationToken.None);

    /// <summary>A CMS from the test kit over <see cref="Content"/>, with the signer and the test intermediate embedded.</summary>
    public static byte[] KitSign(X509Certificate2 signer, CmsSpec spec, byte[]? content = null, IReadOnlyList<X509Certificate2>? chain = null)
    {
        chain ??= [signer, TestPki.Shared.Intermediate];
        return CmsKit.Build(CryptographicOperations.HashData(spec.Hash, content ?? Content), signer, chain, spec);
    }

    public static string WarningsOf(CmsSignerResult r) => string.Join("; ", r.Warnings);

    public static CmsSigningCredential Credential(X509Certificate2 cert) => CmsSigningCredential.FromCertificate(cert, [TestPki.Shared.Intermediate]);

    /// <summary>A time-stamp authority in the test process: answers a request with a TimeStampResp signed by the test authority.</summary>
    public sealed class TestTsa
    {
        public int Calls { get; private set; }

        public CmsTimestampRequest? Last { get; private set; }

        public bool WrongImprint { get; init; }

        public bool WrongNonce { get; init; }

        public bool DropNonce { get; init; }

        public bool Refuse { get; init; }

        public bool BareToken { get; init; }

        public DateTimeOffset Time { get; init; } = DateTimeOffset.UtcNow;

        public byte[] Answer(CmsTimestampRequest request)
        {
            Calls++;
            Last = request;
            if (Refuse)
            {
                return Der.Seq(Der.Seq(Der.Int(2)));
            }

            byte[] imprint = request.MessageImprint.ToArray();
            if (WrongImprint)
            {
                imprint[0] ^= 0x55;
            }

            byte[]? nonce = DropNonce ? null : request.Nonce.ToArray();
            if (WrongNonce && nonce is not null)
            {
                nonce[^1] ^= 0x33;
            }

            byte[] token = CmsKit.Timestamp(imprint, request.HashAlgorithm, Time, null, nonce);
            return BareToken ? token : Der.Seq(Der.Seq(Der.Int(0)), token);
        }

        public CmsTimestampCallback Callback => Answer;
    }
}
