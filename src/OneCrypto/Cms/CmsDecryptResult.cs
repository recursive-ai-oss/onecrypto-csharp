namespace RecursiveAI.OneCrypto;

/// <summary>
/// What a CMS decryption produced and what protected it (RFC 5652 §6.3, RFC 5083, RFC 5084). Returned by the <c>DecryptWithReport</c> methods, so that a caller
/// who decrypted CBC content can see that nothing authenticated it. A successful decryption of CBC content proves only that the padding was well formed;
/// the content may have been altered in any block but the last, so rely on an outer signature or MAC.
/// </summary>
public sealed class CmsDecryptResult
{
    internal CmsDecryptResult(byte[] content, string algorithm, bool authenticated)
    {
        Content = content;
        ContentEncryptionAlgorithm = algorithm;
        Authenticated = authenticated;
        Reasons = authenticated ? [] : ["cipher.cbc.unauthenticated.decrypt"];
    }

    /// <summary>The decrypted content.</summary>
    public byte[] Content { get; }

    /// <summary>The content-encryption algorithm in readable form, for example <c>AES-256-CBC</c> or <c>AES-256-GCM</c>.</summary>
    public string ContentEncryptionAlgorithm { get; }

    /// <summary>
    /// True when the content's integrity was checked by the cipher mode itself (AES-GCM and AES-CCM in AuthEnvelopedData); false for CBC, whose padding check
    /// is not an integrity check.
    /// </summary>
    public bool Authenticated { get; }

    /// <summary>The policy rules that name the weakness, using the identifiers of <see cref="Policy.PolicyDecision.Rule"/>: <c>cipher.cbc.unauthenticated.decrypt</c> for CBC; empty when <see cref="Authenticated"/>.</summary>
    public IReadOnlyList<string> Reasons { get; }
}
