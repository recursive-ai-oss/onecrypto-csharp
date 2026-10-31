using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Pem;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.X509;

/// <summary>
/// Reads the published vector suites (x509-limbo certificates and CRLs, Wycheproof public keys and signatures) through the models.
/// Skipped unless <c>ONECRYPTO_LIMBO</c> (path of limbo.json) or <c>ONECRYPTO_WYCHEPROOF</c> (the testvectors_v1 folder) is set.
/// </summary>
public class CorpusTests
{
    private static readonly string[] Curves = ["secp256r1", "secp384r1", "secp521r1", "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"];

    // Counts go to the console and, when ONECRYPTO_REPORT names a file, are appended there too (a passing test shows no console output).
    private static void Report(string line)
    {
        Console.WriteLine(line);
        string? path = Environment.GetEnvironmentVariable("ONECRYPTO_REPORT");
        if (!string.IsNullOrEmpty(path))
        {
            File.AppendAllText(path, line + "\n");
        }
    }

    private static string? LimboPath => Environment.GetEnvironmentVariable("ONECRYPTO_LIMBO");

    private static string? WycheproofPath => Environment.GetEnvironmentVariable("ONECRYPTO_WYCHEPROOF");

    private static IEnumerable<string> LimboPems(JsonElement testcase, string field)
    {
        if (testcase.TryGetProperty(field, out JsonElement v))
        {
            if (v.ValueKind == JsonValueKind.String)
            {
                yield return v.GetString()!;
            }
            else if (v.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement e in v.EnumerateArray())
                {
                    yield return e.GetString()!;
                }
            }
        }
    }

    // Touches every decoded view of a certificate. Anything but a typed parse error escaping here is a bug.
    private static void Exercise(Certificate c)
    {
        _ = c.Subject.ToString();
        _ = c.Issuer.ToString();
        _ = c.IsSelfIssued;
        _ = c.PublicKey.KeySizeBits;
        _ = c.PublicKey.CurveOid;
        _ = c.SignatureAlgorithm.Name;
        _ = c.TbsSignatureAlgorithm.Name;
        _ = c.IsDer;
        _ = c.ToString();
        foreach (Extension e in c.Extensions)
        {
            _ = e.Oid;
        }

        TryAll(c.Extensions);
        _ = c.VerifySignature(c.PublicKey);
    }

    private static void TryAll(ExtensionCollection x)
    {
        x.TryGet(out BasicConstraints? _);
        x.TryGet(out KeyUsageExtension? _);
        x.TryGet(out ExtendedKeyUsage? _);
        x.TryGet(out SubjectAlternativeName? _);
        x.TryGet(out IssuerAlternativeName? _);
        x.TryGet(out SubjectKeyIdentifier? _);
        x.TryGet(out AuthorityKeyIdentifier? _);
        x.TryGet(out NameConstraints? _);
        x.TryGet(out CertificatePolicies? _);
        x.TryGet(out PolicyMappings? _);
        x.TryGet(out PolicyConstraints? _);
        x.TryGet(out InhibitAnyPolicy? _);
        x.TryGet(out CrlDistributionPoints? _);
        x.TryGet(out FreshestCrl? _);
        x.TryGet(out AuthorityInfoAccess? _);
        x.TryGet(out SubjectInfoAccess? _);
        x.TryGet(out CrlNumber? _);
        x.TryGet(out DeltaCrlIndicator? _);
        x.TryGet(out IssuingDistributionPoint? _);
    }

    private static string? Differences(Certificate c, X509Certificate2 b)
    {
        if (!b.SubjectName.RawData.AsSpan().SequenceEqual(c.Subject.Encoded.Span))
        {
            return "subject";
        }

        if (!b.IssuerName.RawData.AsSpan().SequenceEqual(c.Issuer.Encoded.Span))
        {
            return "issuer";
        }

        static ReadOnlySpan<byte> Trim(ReadOnlySpan<byte> s)
        {
            while (s.Length > 1 && s[0] == 0)
            {
                s = s[1..];
            }

            return s;
        }

        if (!Trim(b.SerialNumberBytes.Span).SequenceEqual(Trim(c.SerialNumber.Span)))
        {
            return "serial";
        }

        if (b.NotBefore.ToUniversalTime() != c.NotBefore.UtcDateTime || b.NotAfter.ToUniversalTime() != c.NotAfter.UtcDateTime)
        {
            return "validity";
        }

        if (!b.Extensions.Select(e => (Oid: e.Oid!.Value!, e.Critical)).SequenceEqual(c.Extensions.Select(e => (Oid: e.Oid, e.Critical))))
        {
            return "extensions";
        }

        if (b.PublicKey.Oid.Value != c.PublicKey.Algorithm.Oid || !b.PublicKey.EncodedKeyValue.RawData.AsSpan().SequenceEqual(c.PublicKey.KeyBits.Span))
        {
            return "spki";
        }

        return null;
    }

    [Fact]
    public void LimboCertificatesAndCrlsParseOrFailTyped()
    {
        Assert.SkipWhen(LimboPath is null, "ONECRYPTO_LIMBO is not set");
        using FileStream fs = File.OpenRead(LimboPath!);
        using JsonDocument doc = JsonDocument.Parse(fs);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        int certs = 0, certOk = 0, certTyped = 0, pemBad = 0, crls = 0, crlOk = 0, crlTyped = 0, bclLoaded = 0, bclRefused = 0, same = 0;
        var diffs = new Dictionary<string, int>();
        var diffExamples = new List<string>();
        foreach (JsonElement tc in doc.RootElement.GetProperty("testcases").EnumerateArray())
        {
            foreach (string field in new[] { "trusted_certs", "untrusted_intermediates", "peer_certificate" })
            {
                foreach (string pem in LimboPems(tc, field))
                {
                    if (!seen.Add(pem))
                    {
                        continue;
                    }

                    certs++;
                    if (!PemCodec.TryParse(pem, PemMode.Lax, out PemBlock? block, out _))
                    {
                        pemBad++;
                        continue;
                    }

                    byte[] der = block!.Data;
                    Certificate c;
                    try
                    {
                        c = Certificate.Parse(new ReadOnlyMemory<byte>(der));
                    }
                    catch (X509ParseException e)
                    {
                        certTyped++;
                        bool platformLoads;
                        try
                        {
                            X509CertificateLoader.LoadCertificate(der).Dispose();
                            platformLoads = true;
                        }
                        catch (CryptographicException)
                        {
                            platformLoads = false;
                        }

                        Report($"  rejected {tc.GetProperty("id").GetString()}: {e.Message} (platform loads it: {platformLoads})");
                        continue;
                    }

                    certOk++;
                    Assert.True(c.Encoded.Span.SequenceEqual(der), "re-encoding must return the received bytes");
                    Exercise(c);
                    X509Certificate2? b = null;
                    try
                    {
                        b = X509CertificateLoader.LoadCertificate(der);
                    }
                    catch (CryptographicException)
                    {
                        bclRefused++;
                    }

                    if (b is not null)
                    {
                        using (b)
                        {
                            bclLoaded++;
                            string? d = Differences(c, b);
                            if (d is null)
                            {
                                same++;
                            }
                            else
                            {
                                diffs[d] = diffs.GetValueOrDefault(d) + 1;
                                if (diffExamples.Count < 10)
                                {
                                    diffExamples.Add($"{d}: {tc.GetProperty("id").GetString()}");
                                }
                            }
                        }
                    }
                }
            }

            foreach (string pem in LimboPems(tc, "crls"))
            {
                if (!seen.Add(pem))
                {
                    continue;
                }

                crls++;
                if (!PemCodec.TryParse(pem, PemMode.Lax, out PemBlock? block, out _))
                {
                    pemBad++;
                    continue;
                }

                try
                {
                    CertificateRevocationList l = CertificateRevocationList.Parse(new ReadOnlyMemory<byte>(block!.Data));
                    crlOk++;
                    Assert.True(l.Encoded.Span.SequenceEqual(block.Data));
                    _ = l.Issuer.ToString();
                    _ = l.Entries.Count();
                    TryAll(l.Extensions);
                }
                catch (X509ParseException)
                {
                    crlTyped++;
                }
            }
        }

        Report($"limbo: certificates {certs} distinct, parsed {certOk}, typed-rejected {certTyped}, PEM-rejected {pemBad}; CRLs {crls}, parsed {crlOk}, typed-rejected {crlTyped}");
        Report($"limbo differential vs X509Certificate2: loaded {bclLoaded}, refused by platform {bclRefused}, identical {same}, differences {string.Join(", ", diffs.Select(p => p.Key + "=" + p.Value))}");
        foreach (string e in diffExamples)
        {
            Report("  " + e);
        }

        Assert.True(certOk > 0);
        Assert.Empty(diffs);
    }

    [Fact]
    public void WycheproofKeysAndSignaturesThroughTheModels()
    {
        Assert.SkipWhen(WycheproofPath is null, "ONECRYPTO_WYCHEPROOF is not set");
        int files = 0, keys = 0, keyRejected = 0, sigs = 0, mustPass = 0, mustFail = 0;
        var failures = new List<string>();
        foreach (string file in Directory.EnumerateFiles(WycheproofPath!, "*_test.json").OrderBy(f => f, StringComparer.Ordinal))
        {
            string name = Path.GetFileName(file);
            bool ecdsa = Curves.Any(c => name.StartsWith("ecdsa_" + c + "_", StringComparison.Ordinal))
                && !name.Contains("p1363", StringComparison.Ordinal) && !name.Contains("sha3", StringComparison.Ordinal) && !name.Contains("sha224", StringComparison.Ordinal) && !name.Contains("shake", StringComparison.Ordinal);
            bool rsa = name.StartsWith("rsa_signature_", StringComparison.Ordinal) && !name.Contains("sha3", StringComparison.Ordinal) && !name.Contains("sha512_2", StringComparison.Ordinal) && !name.Contains("sha224", StringComparison.Ordinal);
            bool rsaHashKnown = rsa && (name.Contains("sha256", StringComparison.Ordinal) || name.Contains("sha384", StringComparison.Ordinal) || name.Contains("sha512", StringComparison.Ordinal) || name.Contains("sha1", StringComparison.Ordinal));
            if (!ecdsa && !rsaHashKnown && !name.StartsWith("eddsa", StringComparison.Ordinal) && !name.StartsWith("ed448", StringComparison.Ordinal))
            {
                continue;
            }

            files++;
            using JsonDocument doc = JsonDocument.Parse(File.ReadAllBytes(file));
            foreach (JsonElement g in doc.RootElement.GetProperty("testGroups").EnumerateArray())
            {
                string? keyHex = g.TryGetProperty("publicKeyDer", out JsonElement kd) ? kd.GetString() : g.TryGetProperty("keyDer", out JsonElement kd2) ? kd2.GetString() : null;
                if (keyHex is null)
                {
                    continue;
                }

                keys++;
                if (!PublicKeyInfo.TryParse(Convert.FromHexString(keyHex), out PublicKeyInfo? key))
                {
                    keyRejected++;
                    continue;
                }

                Assert.NotEqual(KeyAlgorithm.Unknown, key!.KeyAlgorithm);
                if (!ecdsa && !rsaHashKnown)
                {
                    continue;
                }

                string sha = g.GetProperty("sha").GetString()!;
                AlgorithmIdentifier alg = ecdsa
                    ? AlgorithmIdentifier.Create(sha switch { "SHA-256" => KnownOids.EcdsaSha256, "SHA-384" => KnownOids.EcdsaSha384, "SHA-512" => KnownOids.EcdsaSha512, _ => KnownOids.EcdsaSha1 })
                    : AlgorithmIdentifier.WithNull(sha switch { "SHA-256" => KnownOids.Sha256WithRsa, "SHA-384" => KnownOids.Sha384WithRsa, "SHA-512" => KnownOids.Sha512WithRsa, _ => KnownOids.Sha1WithRsa });
                foreach (JsonElement t in g.GetProperty("tests").EnumerateArray())
                {
                    string result = t.GetProperty("result").GetString()!;
                    if (result == "acceptable")
                    {
                        continue;
                    }

                    sigs++;
                    SignatureVerification v = key.VerifySignature(alg, Convert.FromHexString(t.GetProperty("msg").GetString()!), Convert.FromHexString(t.GetProperty("sig").GetString()!));
                    if (result == "valid")
                    {
                        mustPass++;
                        if (!v.IsValid)
                        {
                            failures.Add($"{name} #{t.GetProperty("tcId").GetInt32()} valid but {v.Status}: {v.Reason}");
                        }
                    }
                    else
                    {
                        mustFail++;
                        if (v.IsValid)
                        {
                            failures.Add($"{name} #{t.GetProperty("tcId").GetInt32()} accepted an invalid signature");
                        }
                    }
                }
            }
        }

        Report($"wycheproof: files {files}, public keys {keys} (rejected {keyRejected}), signatures checked {sigs} (valid {mustPass}, invalid {mustFail}), failures {failures.Count}");
        foreach (string f in failures.Take(60))
        {
            Report("  " + f);
        }

        Assert.Empty(failures);
    }
}
