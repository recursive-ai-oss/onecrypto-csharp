using System.Text;
using RecursiveAI.OneCrypto;

namespace OneCrypto.Smoke;

/// <summary>
/// <c>Crypto.Load</c> in an app that has to be trimmed, AOT-compiled or run in the browser: a PEM certificate chain with text around it
/// and a public key everywhere; where the platform has PBKDF2, also an encrypted PKCS#8 key loaded through the password callback.
/// The certificate and key are a generated test pair whose private half was discarded.
/// </summary>
internal static class LoadSmoke
{
    private const string Certificate =
        """
        -----BEGIN CERTIFICATE-----
        MIIBYDCCAQWgAwIBAgIUa+4x4IgAdFl9D8Txz8vzarI6fbUwCgYIKoZIzj0EAwIw
        HTEbMBkGA1UEAwwSc21va2UuZXhhbXBsZS50ZXN0MCAXDTI2MTAzMTE1NTIyMVoY
        DzIxMjYxMDA3MTU1MjIxWjAdMRswGQYDVQQDDBJzbW9rZS5leGFtcGxlLnRlc3Qw
        WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATszCdhxyMoSBdQyqYPJC8nZHnnK08m
        Ml7VKIrGMXxkwwdphvIBVG0bwfl5dDEyh5DZl6xnxZhcEvesNsGgL6+goyEwHzAd
        BgNVHQ4EFgQU2tZYz13iddbxYDRwuXUeJIFwAAIwCgYIKoZIzj0EAwIDSQAwRgIh
        AIkpBvMTZspZyrRtQhNQTa0SQNk0orWknDn/YHWDZCjfAiEA//x8l4K+z+JbJgR+
        CS8hJQAiAUXqPnW6dNTLew7zOI0=
        -----END CERTIFICATE-----

        """;

    private const string PublicKey =
        """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7MwnYccjKEgXUMqmDyQvJ2R55ytP
        JjJe1SiKxjF8ZMMHaYbyAVRtG8H5eXQxMoeQ2ZesZ8WYXBL3rDbBoC+voA==
        -----END PUBLIC KEY-----

        """;

    public static bool Run(bool withPassword)
    {
        bool ok = true;
        string chain = "chain for smoke\n" + Certificate + "between\n" + Certificate;
        using (LoadedItems items = Crypto.Load(Encoding.ASCII.GetBytes(chain)))
        {
            ok &= items.Certificates.Count == 2 && items.Format == "PEM"
                && items.Certificates[0].Subject.ToString().Contains("smoke.example.test", StringComparison.Ordinal);
        }

        using (LoadedItems items = Crypto.Load(Encoding.ASCII.GetBytes(PublicKey)))
        {
            ok &= items.PublicKeys.Count == 1 && items.PublicKeys[0].KeyAlgorithm == KeyAlgorithm.EllipticCurve;
        }

        ok &= !Crypto.TryLoad("not a key"u8, out _, out CryptoLoadException? error) && error!.Error == CryptoLoadError.Unrecognized;

        if (withPassword)
        {
            using var ed = RecursiveAI.OneCrypto.Primitives.Ed25519PrivateKey.Generate();
            using RecursiveAI.OneCrypto.Pkcs.PrivateKeyInfo pk = RecursiveAI.OneCrypto.Pkcs.PrivateKeyInfo.FromEd25519(ed);
            string pem = pk.Encrypt("pw", new RecursiveAI.OneCrypto.Pkcs.Pbes2Options { Iterations = 100 }).ToPem();
            using LoadedItems keys = Crypto.Load(Encoding.ASCII.GetBytes(pem), _ => "pw");
            ok &= keys.PrivateKeys.Count == 1 && keys.PrivateKeys[0].Signing is not null;
            byte[] sig = keys.PrivateKeys[0].Signing!.Sign("smoke"u8, keys.PrivateKeys[0].Signing!.DefaultSpec);
            ok &= keys.PrivateKeys[0].Signing!.DefaultSpec.Verify(keys.PrivateKeys[0].PublicKey!, "smoke"u8, sig).IsValid;
            ok &= Crypto.TryLoad(Encoding.ASCII.GetBytes(pem), out _, out CryptoLoadException? denied, _ => "no") is false && denied!.Error == CryptoLoadError.WrongPasswordOrCorrupt;
        }

        return ok;
    }
}
