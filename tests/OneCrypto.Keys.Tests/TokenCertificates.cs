using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Keys.Tests;

/// <summary>Self-signed certificates whose key is on the token, signed by the token.</summary>
internal static class TokenCertificates
{
    internal static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    internal static Certificate SelfSigned(string commonName, ISigningKey key, KeyUsages usages, SignatureSpec? spec = null) =>
        CertificateBuilder.CreateSelfSigned(
            new CertificateOptions
            {
                Subject = DistinguishedName.Create(("2.5.4.10", "OneCrypto Tests"), ("2.5.4.3", commonName)),
                NotBefore = Now.AddYears(-1),
                NotAfter = Now.AddYears(5),
                Extensions =
                [
                    Extension.Create(new BasicConstraints(false, null), critical: true),
                    Extension.Create(new KeyUsageExtension(usages), critical: true),
                ],
            },
            X509Signer.FromKey(key, spec));
}
