using RecursiveAI.OneCrypto.Policy;

namespace RecursiveAI.OneCrypto;

/// <summary>Where the CMS operations ask the <see cref="CryptoPolicy"/>: the content cipher, and the recipient keys' sizes.</summary>
internal static class CmsPolicyChecks
{
    /// <summary>
    /// Judges the content cipher of a message being written or read. Authenticated modes (GCM, CCM) pass. CBC, which RFC 5652 §6.3 specifies and S/MIME
    /// uses everywhere, has no integrity of its own: <see cref="CryptoPolicy.CheckContentCipher"/> flags it, so <c>Standard</c> still reads and writes it
    /// while <c>Strict</c> refuses it. Triple-DES is a legacy cipher and follows <see cref="CryptoPolicy.LegacyCiphers"/>.
    /// </summary>
    public static PolicyReport Cipher(CryptoPolicy policy, ContentCipher cipher, CryptoUse use)
    {
        var decisions = new List<PolicyDecision>();
        decisions.Add(policy.CheckCipher(cipher.Kind == CipherKind.TripleDesCbc ? CipherAlgorithm.TripleDes : CipherAlgorithm.Aes, authenticated: true, use));
        if (!cipher.Authenticated)
        {
            decisions.Add(policy.CheckContentCipher(cipher.Name, use));
        }

        return new PolicyReport(decisions);
    }

    /// <summary>The recipients' public keys, judged as keys for new data.</summary>
    public static PolicyReport Recipients(CryptoPolicy policy, IReadOnlyList<CmsRecipient> recipients)
    {
        var decisions = new List<PolicyDecision>();
        foreach (CmsRecipient r in recipients)
        {
            if (r.PublicKey is { } key)
            {
                decisions.Add(policy.CheckKey(key, CryptoUse.Encrypt, default));
            }
        }

        return new PolicyReport(decisions);
    }

    public static void ThrowIfRejected(PolicyReport report)
    {
        if (!report.IsAllowed)
        {
            throw new PolicyViolationException(report);
        }
    }

    /// <summary>Before any key operation on a message being opened: the cipher the message names and the key that would open it.</summary>
    public static void BeforeDecrypt(CmsDecryptOptions? options, ContentCipher? cipher, CmsDecryptionKey key)
    {
        if (options?.Policy is not { } policy)
        {
            return;
        }

        DateTimeOffset at = options.ReferenceTime ?? throw new ArgumentException("A policy needs a reference time: set CmsDecryptOptions.ReferenceTime.", nameof(options));
        var decisions = new List<PolicyDecision>();
        if (cipher is not null)
        {
            decisions.AddRange(Cipher(policy, cipher, CryptoUse.Decrypt).Decisions);
        }

        if (key.PublicKey is { } pub)
        {
            decisions.Add(policy.CheckKey(pub, CryptoUse.Decrypt, at));
        }

        ThrowIfRejected(new PolicyReport(decisions));
    }
}
