using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OneCrypto.Tests.Support;

/// <summary>Shared pieces for tests that read raw CMS built by the independent test kit.</summary>
internal static class CmsFixture
{
    /// <summary>The bytes every kit signature covers.</summary>
    public static readonly byte[] Content = "Hello signing world"u8.ToArray();

    /// <summary>A CMS from the test kit over <see cref="Content"/> (or the given bytes), with the signer and the test intermediate embedded.</summary>
    public static byte[] KitSign(X509Certificate2 signer, CmsSpec spec, byte[]? content = null, IReadOnlyList<X509Certificate2>? chain = null)
    {
        chain ??= [signer, TestPki.Shared.Intermediate];
        return CmsKit.Build(CryptographicOperations.HashData(spec.Hash, content ?? Content), signer, chain, spec);
    }
}
