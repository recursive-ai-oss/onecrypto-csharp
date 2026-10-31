using OneCrypto.Fuzz;

namespace OneCrypto.Tests.Pkcs;

/// <summary>Deterministic byte-level mutation of the fuzz seeds through the container targets: nothing but the library's typed errors may escape.</summary>
public class FuzzSmokeTests
{
    private delegate void Target(ReadOnlySpan<byte> data);

    [Theory]
    [InlineData("pkcs8")]
    [InlineData("pkcs12")]
    [InlineData("ssh")]
    public void MutatedSeedsOnlyRaiseTypedErrors(string name)
    {
        (Target run, IEnumerable<byte[]> seeds) = name switch
        {
            "pkcs8" => ((Target)Pkcs8Target.Run, Pkcs8Target.Seeds()),
            "pkcs12" => (Pkcs12Target.Run, Pkcs12Target.Seeds()),
            _ => (SshTarget.Run, SshTarget.Seeds()),
        };
        byte[][] corpus = [.. seeds];
        var rnd = new Random(2024);
        for (int i = 0; i < 4000; i++)
        {
            var buf = new List<byte>(corpus[rnd.Next(corpus.Length)]);
            for (int e = 1 + rnd.Next(6); e > 0 && buf.Count > 0; e--)
            {
                int at = rnd.Next(buf.Count);
                switch (rnd.Next(4))
                {
                    case 0: buf[at] = (byte)rnd.Next(256); break;
                    case 1: buf[at] ^= (byte)(1 << rnd.Next(8)); break;
                    case 2: buf.RemoveRange(at, Math.Min(1 + rnd.Next(12), buf.Count - at)); break;
                    default: buf.Insert(at, (byte)rnd.Next(256)); break;
                }
            }

            run([.. buf]);
        }
    }

    /// <summary>Found by the PKCS#12 fuzz target: a PBMAC1 file naming hmacWithSHA224, which the platform's PBKDF2 does not have, escaped as a platform exception.</summary>
    [Fact]
    public void Pbmac1WithAnUnavailableHashIsReportedAsUnsupported()
    {
        byte[] repro = Convert.FromBase64String("MIID+wIBAzCCA2YGCSqGSIb3DQEHAaCCA1cEggNTMIIDTzCCAUsGCSqGSIb3DQEHAaCCATwEggE4MIIBNDCCATAGCyqGSIb3DQEMCgECoIH5MIH2MGEGCSqGSIb3DQEFDTBUMDMGCSqGSIb3DQEFDDAmBBBzu3eU3T4gd1luLUydU5HcAgFkAgEgMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBB7WXQ1Ni4A54/A9mcHufq3BIGQZqhcXA4zL3QZHo0/tEXMCLQ847VqqWovW7vqOGC7bCDOl+/rlhOsKmarCJWKW2J/Idy6+wzqS/oIDd8igV/QSt4+ijwqAd1h8CysMbWTUg+E0RLUnYEA5zITKQTDy+WTdAY0U0zQxwigwrr3gRoE3zGj4UA9GFWJI7ERxRgBVhUZPZylTLFrC3Y6498BTXrnMSUwIwYJxYZIhvcNAQkVMRYEFB6fCvZ8vgQLW2yKmn3GlGiuyFGDMIIB/AYJKoZIhvcNAQcGoIIB7TCCAekCAQAwggHiBgkqhkiG9w0BBwEwYQYJKoZIhvcNAQUNMFQwMwYJKoZIhvcNAQUMMCYEEKBAsU2WVMBRVlUlCYH68ssCAWQCASAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEB9SJauhhi5b9LrJJwEq9BGAggFwnJOhubD+OEPpplYpKm3KXYprR8v3EO0Umqbl33uA5wmCBVy9iULRyi/DAzwIlQo/w9zbIKCngUt1ipNSKgRH0dZCfHdkqb8qyo7Jqwv3VRz1hzOngtCK6pwxtGcfhk7FvlhiPXlsqzwfiRbYTj3XOebq8RgdlVfi1GYqmQvcThahiYAcrhVIo6EZf9lMtHEtg/dw7KvA9kv6wN735DdARg+wTn4dFCFh8pb0FDe4yp65qsVf6rDp++MAMcjSo6jeoj4lEnmxTIuRZlwM21OpzqUyDFJLDJQZTnXhEV2whzc7jb5jKr05OmUUAgi80nD7DK7Y7166Mflbk8kTtuq7oyYjvzV9+kWY+T65X5x/KUKzqfSPfI/RF+6j8yi924p1VzPblnlPQIWRekaexfQb1actwUMKl8GE965LyXsqsX28lJcFEjZGd/wSn47Jupo/iVcU6JTlDdpg9jqkR8eQLM0/joWtZu0oRSIrF5jZkaQwgYswdDBQBgkqhkiG9w0BBQ4wQzAzBgkqhkiG9w0BBQwwJgQQNrYR+Bhz4Mp+QHgClCHWHwIBZAIBIDAMBggqhkiG9w0CCAUAMAwGCCqGSIb3DQIKBQAEIPuXVsG/noAec4Numz7jok3Yty5KBwdce2Mjl3Hb1mY6BBA2thH4GHPgyn5AeAKUIdYfAgEB");
        Pkcs12Target.Run(repro);
        var file = RecursiveAI.OneCrypto.Pkcs.Pkcs12File.Parse(repro);
        Assert.Equal(RecursiveAI.OneCrypto.Pkcs.PkcsStatus.UnsupportedAlgorithm, file.VerifyMac("fuzz"));
    }
}
