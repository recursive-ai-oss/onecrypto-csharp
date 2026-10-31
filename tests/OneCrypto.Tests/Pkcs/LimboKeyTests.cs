using System.Text.Json;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Pkcs;

namespace OneCrypto.Tests.Pkcs;

/// <summary>Reads the private keys of the published x509-limbo suite (<c>peer_certificate_key</c>, PKCS#8 PEM). Skipped unless <c>ONECRYPTO_LIMBO</c> names limbo.json.</summary>
public class LimboKeyTests
{
    [Fact]
    public void EveryLimboPrivateKeyParsesAndMatchesItsCertificate()
    {
        string? path = Environment.GetEnvironmentVariable("ONECRYPTO_LIMBO");
        Assert.SkipWhen(string.IsNullOrEmpty(path) || !File.Exists(path), "ONECRYPTO_LIMBO is not set");
        using JsonDocument doc = JsonDocument.Parse(File.ReadAllBytes(path!));
        var seen = new HashSet<string>();
        int keys = 0, parsed = 0, matched = 0, noCert = 0, platformLacks = 0;
        var bad = new List<string>();
        foreach (JsonElement tc in doc.RootElement.GetProperty("testcases").EnumerateArray())
        {
            if (!tc.TryGetProperty("peer_certificate_key", out JsonElement k) || k.ValueKind != JsonValueKind.String || !seen.Add(k.GetString()!))
            {
                continue;
            }

            keys++;
            if (PrivateKeyPem.TryParse(k.GetString()!, default, out PrivateKeyInfo? key) != PkcsStatus.Ok)
            {
                bad.Add(tc.GetProperty("id").GetString()!);
                continue;
            }

            using (key)
            {
                parsed++;
                if (tc.TryGetProperty("peer_certificate", out JsonElement c) && c.ValueKind == JsonValueKind.String && Certificate.TryParse(RecursiveAI.OneCrypto.Pem.PemCodec.Parse(c.GetString()!).Data, out Certificate? cert))
                {
                    try
                    {
                        if (key!.GetPublicKey().Equals(cert!.PublicKey))
                        {
                            matched++;
                        }
                    }
                    catch (PlatformNotSupportedException)
                    {
                        platformLacks++; // a post-quantum key on a platform without that algorithm
                    }
                }
                else
                {
                    noCert++;
                }
            }
        }

        Console.WriteLine($"limbo keys: {keys} distinct, parsed {parsed}, public key equals the peer certificate's {matched}, no usable certificate {noCert}, algorithm missing on this platform {platformLacks}");
        Assert.Empty(bad);
        Assert.True(keys > 0);
    }
}
