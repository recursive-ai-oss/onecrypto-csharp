using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Internal;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Pem;
using RecursiveAI.OneCrypto.Pkcs;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.Tsp;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Smoke;

/// <summary>
/// The suite that runs in a browser engine, under Node and natively with the same code: parsing and inspecting, signature
/// verification through the platform-gap fallbacks, CMS and time-stamp verification, path validation and the typed refusals where
/// the browser has no primitive. Each case prints one line, <c>CASE area id status verdict detail</c> separated by tabs. The status
/// says whether the case met its expectation; the verdict is the observed outcome in words that do not depend on the host, so a
/// script can compare the hosts case by case. The data is the embedded <c>suite-data.json</c> (tools/gen-browser-data.py).
/// </summary>
internal static class BrowserSuite
{
    private static readonly DateTimeOffset FixtureTime = new(2026, 11, 15, 0, 0, 0, TimeSpan.Zero);
    private static readonly Dictionary<string, int> Counts = [];
    private static readonly Dictionary<string, byte[]> Fixtures = new(StringComparer.Ordinal);

    public static int Run(string? only, bool forceFallbacks = false)
    {
        using IDisposable? forced = forceFallbacks ? RecursiveAI.OneCrypto.Internal.Platform.ForceFallbacks() : null;
        using Stream? s = typeof(BrowserSuite).Assembly.GetManifestResourceStream("suite-data.json");
        if (s is null)
        {
            Console.WriteLine("FATAL\tsuite-data.json is not embedded");
            return 2;
        }

        using JsonDocument doc = JsonDocument.Parse(s);
        JsonElement root = doc.RootElement;
        foreach (JsonProperty p in root.GetProperty("fixtures").EnumerateObject())
        {
            Fixtures[p.Name] = Convert.FromBase64String(p.Value.GetString()!);
        }

        Console.WriteLine($"HOST\tbrowser={OperatingSystem.IsBrowser()}\tforced={forceFallbacks}\tos={OsName()}\truntime={Environment.Version}");
        (string Name, Action Body)[] areas =
        [
            ("platform", Platform_),
            ("parse-fixtures", ParseFixtures),
            ("parse-limbo-certs", () => ParseLimboCerts(root)),
            ("load", LoadFixtures),
            ("kdf", Kdfs),
            ("protected-inputs", ProtectedInputs),
            ("verify-wycheproof", () => VerifyWycheproof(root)),
            ("ssh", SshKeys),
            ("cms", CmsVerify),
            ("timestamp", TimestampVerify),
            ("validate-limbo", () => ValidateLimbo(root)),
            ("unsupported", Unsupported),
        ];
        foreach ((string name, Action body) in areas)
        {
            if (only is null || only.Split(',').Contains(name))
            {
                body();
            }
        }

        int failed = Counts.Where(kv => kv.Key.EndsWith("/fail", StringComparison.Ordinal)).Sum(kv => kv.Value);
        Console.WriteLine($"SUMMARY\tfailed={failed}");
        return failed == 0 ? 0 : 1;
    }

    private static string OsName() => OperatingSystem.IsBrowser() ? "browser" : System.Runtime.InteropServices.RuntimeInformation.OSDescription;

    private static void Case(string area, string id, bool passed, string verdict, string detail = "", bool skipped = false)
    {
        string status = skipped ? "skip" : passed ? "pass" : "fail";
        Counts[$"{area}/{status}"] = Counts.GetValueOrDefault($"{area}/{status}") + 1;
        Console.WriteLine($"CASE\t{area}\t{Clean(id)}\t{status}\t{Clean(verdict)}\t{Clean(detail)}");
    }

    private static string Clean(string s) => s.Replace('\t', ' ').Replace('\n', ' ').Replace('\r', ' ');

    // Runs one case; anything that escapes the library as something other than its typed errors is a failure with the exception named.
    // unsupportedInBrowser: the case needs a private-key operation or a cipher the browser lacks, so there the typed refusal is the right answer.
    private static void Guard(string area, string id, Func<(bool Passed, string Verdict, string Detail)> body, bool unsupportedInBrowser = false)
    {
        try
        {
            (bool passed, string verdict, string detail) = body();
            Case(area, id, passed, verdict, detail);
        }
        catch (AlgorithmNotSupportedException e)
        {
            Case(area, id, unsupportedInBrowser && OperatingSystem.IsBrowser(), "AlgorithmNotSupported", e.Message);
        }
        catch (Exception e)
        {
            Case(area, id, false, "exception:" + e.GetType().Name, e.Message);
        }
    }

    // --- platform ---------------------------------------------------------------------------------------------------------

    private static void Platform_()
    {
        // The availability section is compared with docs/availability.md by the script that runs the suite.
        Console.WriteLine("AVAILABILITY-BEGIN");
        Console.Write(RecursiveAI.OneCrypto.Internal.Platform.AvailabilitySection());
        Console.WriteLine("AVAILABILITY-END");
        Case("platform", "rsa-verify-provider", true, RecursiveAI.OneCrypto.Internal.Platform.RsaVerify.ToString());
        Case("platform", "ecdsa-p256-verify-provider", true, RecursiveAI.OneCrypto.Internal.Platform.EcdsaVerify(EcCurve.NistP256).ToString());
        Case("platform", "sha3-256-provider", true, RecursiveAI.OneCrypto.Internal.Platform.Sha3(256).ToString());
        Case("platform", "sha256-hash", Convert.ToHexStringLower(SHA256.HashData("abc"u8)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "ok");
        // What the runtime itself offers, probed directly so the report says what the browser lacks. CA1416 is silenced for these probes
        // only, as in the other smoke apps: the point is to call APIs the platform is annotated as lacking.
#pragma warning disable CA1416
        try
        {
            _ = Rfc2898DeriveBytes.Pbkdf2("pw"u8, "salt"u8, 1, HashAlgorithmName.SHA256, 16);
            Case("platform", "runtime-pbkdf2", true, "works");
        }
        catch (PlatformNotSupportedException)
        {
            Case("platform", "runtime-pbkdf2", true, "PlatformNotSupported");
        }

        try
        {
            using Aes aes = Aes.Create();
            aes.Key = new byte[16];
            _ = aes.EncryptEcb(new byte[16], PaddingMode.None);
            Case("platform", "runtime-aes", true, "works");
        }
        catch (PlatformNotSupportedException)
        {
            Case("platform", "runtime-aes", true, "PlatformNotSupported");
        }

#pragma warning restore CA1416
        Case("platform", "hmac-sha256", Convert.ToHexStringLower(HMACSHA256.HashData("k"u8, "abc"u8)).Length == 64, "ok");
    }

    // --- parse and inspect ------------------------------------------------------------------------------------------------

    private static string Describe(Certificate c) =>
        $"{c.Subject}|{c.SerialNumberValue}|{c.SignatureAlgorithm.Oid}|{c.PublicKey.KeyAlgorithm}|{c.NotBefore.UtcDateTime:O}|{c.NotAfter.UtcDateTime:O}|ext={c.Extensions.Count}";

    private static void ParseFixtures()
    {
        foreach (string name in Fixtures.Keys.Order(StringComparer.Ordinal))
        {
            byte[] bytes = Fixtures[name];
            if (name is "ca-cert.pem" or "rsa.pem" or "p256.pem" or "p384.pem" or "p521.pem" or "ed25519.pem" or "tsa.pem")
            {
                Guard("parse-fixtures", name, () =>
                {
                    Certificate c = Certificate.FromPem(Encoding.ASCII.GetString(bytes));
                    // The key's signature check is the first use of a public-key operation after parsing.
                    bool self = name == "ca-cert.pem" ? c.IsSelfSigned : c.VerifySignature(Certificate.FromPem(Encoding.ASCII.GetString(Fixtures["ca-cert.pem"]))).IsValid;
                    return (self, Describe(c), "signature " + (self ? "verifies" : "does not verify"));
                });
            }
            else if (name == "crl.pem")
            {
                Guard("parse-fixtures", name, () =>
                {
                    CertificateRevocationList crl = CertificateRevocationList.FromPem(Encoding.ASCII.GetString(bytes));
                    var ca = Certificate.FromPem(Encoding.ASCII.GetString(Fixtures["ca-cert.pem"]));
                    SignatureVerification v = crl.VerifySignature(ca);
                    return (v.IsValid && crl.Entries.Count() == 1, $"{crl.Issuer}|revoked={crl.Entries.Count()}|{crl.ThisUpdate.UtcDateTime:O}", v.Status.ToString());
                });
            }
            else if (name.StartsWith("ocsp-", StringComparison.Ordinal))
            {
                Guard("parse-fixtures", name, () =>
                {
                    OcspResponse r = OcspResponse.Parse(bytes);
                    OcspBasicResponse? b = r.BasicResponse;
                    var ca = Certificate.FromPem(Encoding.ASCII.GetString(Fixtures["ca-cert.pem"]));
                    SignatureVerification v = b!.VerifySignature(ca.PublicKey);
                    string state = b.Responses[0].Status.ToString();
                    bool expected = state == (name.Contains("revoked", StringComparison.Ordinal) ? "Revoked" : "Good");
                    return (v.IsValid && expected, $"{r.Status}|{state}|responses={b.Responses.Count}", v.Status.ToString());
                });
            }
            else if (name == "ts.tsq")
            {
                Guard("parse-fixtures", name, () =>
                {
                    TimeStampRequest q = TimeStampRequest.Parse(bytes);
                    return (q.MessageImprint.Length == 32, $"imprint={Convert.ToHexStringLower(q.MessageImprint.Span)[..16]}", "");
                });
            }
            else if (name is "pk8-ed25519.pem" or "pk8-p256.pem")
            {
                Guard("private-keys", name, () =>
                {
                    using PrivateKeyInfo k = PrivateKeyInfo.FromPem(Encoding.ASCII.GetString(bytes));
                    PublicKeyInfo pub = k.GetPublicKey();
                    return (true, $"{k.KeyAlgorithm}|{pub.KeyAlgorithm}|{Convert.ToHexStringLower(SHA256.HashData(pub.Encoded.Span))[..16]}", "");
                }, unsupportedInBrowser: name == "pk8-p256.pem");
            }
        }

        // PEM framing itself.
        Guard("parse-fixtures", "pem-blocks", () =>
        {
            string text = Encoding.ASCII.GetString(Fixtures["ca-cert.pem"]) + "text between\n" + Encoding.ASCII.GetString(Fixtures["p256.pem"]);
            bool ok = PemCodec.TryParseAll(text, PemMode.Lax, out IReadOnlyList<PemBlock> blocks, out _);
            return (ok && blocks.Count == 2, $"blocks={blocks.Count}", "");
        });
    }

    private static void ParseLimboCerts(JsonElement root)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonElement tc in root.GetProperty("limbo").EnumerateArray())
        {
            var pems = new List<string> { tc.GetProperty("peer_certificate").GetString()! };
            foreach (string key in new[] { "trusted_certs", "untrusted_intermediates" })
            {
                foreach (JsonElement e in tc.GetProperty(key).EnumerateArray())
                {
                    pems.Add(e.GetString()!);
                }
            }

            foreach (string pem in pems)
            {
                if (!seen.Add(pem))
                {
                    continue;
                }

                string id = "cert-" + Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(pem)))[..12];
                try
                {
                    Certificate c = Certificate.FromPem(pem);
                    Case("parse-limbo-certs", id, true, Describe(c));
                }
                catch (X509ParseException e)
                {
                    // A certificate limbo built to be malformed may be refused, but only with the typed error.
                    Case("parse-limbo-certs", id, true, "X509ParseException", e.Message);
                }
                catch (Exception e)
                {
                    Case("parse-limbo-certs", id, false, "exception:" + e.GetType().Name, e.Message);
                }
            }
        }
    }

    private static void LoadFixtures()
    {
        foreach (string name in Fixtures.Keys.Order(StringComparer.Ordinal))
        {
            if (name is "VERSION" or "content.txt")
            {
                continue;
            }

            Guard("load", name, () =>
            {
                // No password is offered: a protected file is reported as such, not guessed at.
                bool ok = Crypto.TryLoad(Fixtures[name], out LoadedItems? items, out CryptoLoadException? error);
                if (ok)
                {
                    using (items)
                    {
                        return (true, $"{items!.Format}|certs={items.Certificates.Count}|crls={items.Crls.Count}|keys={items.PrivateKeys.Count}|pub={items.PublicKeys.Count}|ocsp={items.OcspResponses.Count}", "");
                    }
                }

                // Binary containers the loader does not claim (CMS, time-stamp files) are fine to leave unrecognised, as is a protected file without a password.
                return (true, "refused:" + error!.Error, error.Message);
            });
        }
    }

    // The browser has HMAC but no PBKDF2 and no AES: which password-protected inputs does that touch? Each outcome is one of the
    // library's typed ones; the verdicts are what docs/browser.md reports.
    private static void ProtectedInputs()
    {
        foreach (string name in new[] { "pk8-p256-pbes2.pem", "p12-pbes2.p12", "p12-legacy.p12", "p12-plain.p12" })
        {
            Guard("protected-inputs", name + " (Crypto.Load)", () =>
            {
                try
                {
                    using LoadedItems items = Crypto.Load(Fixtures[name], _ => "password");
                    return (true, $"loaded|certs={items.Certificates.Count}|keys={items.PrivateKeys.Count}", "");
                }
                catch (CryptoLoadException e)
                {
                    return (true, "CryptoLoadException:" + e.Error, e.Message);
                }
            });
        }

        Guard("protected-inputs", "p12-plain.p12 (Pkcs12File.Open, no password)", () =>
        {
            Pkcs12File f = Pkcs12File.Parse(Fixtures["p12-plain.p12"]);
            PkcsStatus st = f.TryOpen("", out Pkcs12Contents? contents, requireMac: false);
            using (contents)
            {
                return (st == PkcsStatus.Ok && contents!.Certificates.Count == 2 && contents.PrivateKeys.Count == 1, $"{st}|certs={contents?.Certificates.Count}|keys={contents?.PrivateKeys.Count}", "");
            }
        });
        foreach (string name in new[] { "p12-pbes2.p12", "p12-legacy.p12" })
        {
            Guard("protected-inputs", name + " (Pkcs12File.Parse only)", () =>
            {
                Pkcs12File f = Pkcs12File.Parse(Fixtures[name]);
                return (true, $"parsed|mac={f.MacKind}", "");
            });
        }

        foreach (string name in new[] { "p12-pbes2.p12", "p12-legacy.p12" })
        {
            Guard("protected-inputs", name + " (VerifyMac, right password)", () =>
            {
                PkcsStatus st = Pkcs12File.Parse(Fixtures[name]).VerifyMac("password");
                return (true, st.ToString(), "");
            });
            Guard("protected-inputs", name + " (VerifyMac, wrong password)", () =>
            {
                PkcsStatus st = Pkcs12File.Parse(Fixtures[name]).VerifyMac("passwore");
                return (st == PkcsStatus.WrongPasswordOrCorrupt, st.ToString(), "");
            });
        }

        Guard("protected-inputs", "pk8-p256-pbes2.pem (parse only)", () =>
        {
            EncryptedPrivateKeyInfo e = EncryptedPrivateKeyInfo.FromPem(Encoding.ASCII.GetString(Fixtures["pk8-p256-pbes2.pem"]));
            return (true, "parsed|" + e.EncryptionAlgorithm.Oid, "");
        });
    }

    // The browser runtime has HMAC and, in this runtime version, PBKDF2 over it; these must give the published answers there too.
    private static void Kdfs()
    {
        Guard("kdf", "PBKDF2-HMAC-SHA256 (RFC 7914 section 11)", () =>
        {
            byte[] dk = Rfc2898DeriveBytes.Pbkdf2("passwd"u8, "salt"u8, 1, HashAlgorithmName.SHA256, 64);
            return (Convert.ToHexStringLower(dk).StartsWith("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc", StringComparison.Ordinal), "derived", "");
        });
        Guard("kdf", "scrypt (RFC 7914 section 12, first vector)", () =>
        {
            byte[] dk = Scrypt.DeriveKey([], [], 16, 1, 1, 64);
            return (Convert.ToHexStringLower(dk).StartsWith("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442", StringComparison.Ordinal), "derived", "");
        });
        Guard("kdf", "Argon2id (RFC 9106 section 5.3)", () =>
        {
            byte[] dk = Argon2.DeriveKey(Argon2Type.Argon2id, Filled(1, 32), Filled(2, 16), 32, 3, 4, 32, Filled(3, 8), Filled(4, 12));
            return (Convert.ToHexStringLower(dk) == "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", "derived", "");
        });
    }

    private static byte[] Filled(byte value, int length) => Enumerable.Repeat(value, length).ToArray();

    // --- signatures -------------------------------------------------------------------------------------------------------

    private static HashAlgorithmName Hash(string n) => n switch
    {
        "SHA256" => HashAlgorithmName.SHA256,
        "SHA384" => HashAlgorithmName.SHA384,
        _ => HashAlgorithmName.SHA512,
    };

    private static void VerifyWycheproof(JsonElement root)
    {
        foreach (JsonElement g in root.GetProperty("wycheproof").EnumerateArray())
        {
            string file = g.GetProperty("file").GetString()!;
            string kind = g.GetProperty("kind").GetString()!;
            string area = "verify-wycheproof";
            foreach (JsonElement t in g.GetProperty("tests").EnumerateArray())
            {
                string id = $"{file}#{g.GetProperty("group").GetInt32()}/{t.GetProperty("id").GetInt32()}";
                string expected = t.GetProperty("result").GetString()!;
                byte[] msg = Convert.FromHexString(t.GetProperty("msg").GetString()!);
                byte[] sig = Convert.FromHexString(t.GetProperty("sig").GetString()!);
                try
                {
                    bool accepted;
                    switch (kind)
                    {
                        case "ed25519":
                            accepted = Ed25519.Verify(Convert.FromHexString(g.GetProperty("key").GetString()!), msg, sig);
                            break;
                        case "ed448":
                            accepted = Ed448.Verify(Convert.FromHexString(g.GetProperty("key").GetString()!), msg, [], sig);
                            break;
                        case "ecdsa-der":
                        case "ecdsa-p1363":
                        {
                            PublicKeyInfo key = PublicKeyInfo.Parse(Convert.FromHexString(g.GetProperty("spki").GetString()!));
                            SignatureSpec spec = SignatureSpec.Ecdsa(Hash(g.GetProperty("hash").GetString()!), kind == "ecdsa-der" ? EcdsaSignatureFormat.Der : EcdsaSignatureFormat.Rfc4754);
                            accepted = spec.Verify(key, msg, sig).IsValid;
                            break;
                        }

                        case "rsa-pkcs1":
                        {
                            PublicKeyInfo key = PublicKeyInfo.Parse(Convert.FromHexString(g.GetProperty("spki").GetString()!));
                            accepted = SignatureSpec.RsaPkcs1(Hash(g.GetProperty("hash").GetString()!)).Verify(key, msg, sig).IsValid;
                            break;
                        }

                        default:
                        {
                            // PSS with the group's exact salt length: the public spec verifies any salt, so the vectors that test the salt go to the dispatch.
                            HashAlgorithmName h = Hash(g.GetProperty("hash").GetString()!);
                            byte[] digest = PlatformHash.Digest(h, msg)!;
                            accepted = PlatformSignatures.RsaVerifyPss(Strip(Convert.FromHexString(g.GetProperty("n").GetString()!)), Strip(Convert.FromHexString(g.GetProperty("e").GetString()!)),
                                h, Hash(g.GetProperty("mgfHash").GetString()!), g.GetProperty("sLen").GetInt32(), digest, sig);
                            break;
                        }
                    }

                    // "acceptable" vectors are ones either answer is correct for.
                    bool ok = expected == "acceptable" || accepted == (expected == "valid");
                    Case(area, id, ok, accepted ? "accepted" : "rejected", $"expected {expected}");
                }
                catch (AlgorithmNotSupportedException e)
                {
                    Case(area, id, false, "AlgorithmNotSupported", e.Message);
                }
                catch (Exception e) when (e is ArgumentException or CryptographicException or X509ParseException)
                {
                    // A key or signature the verifier refuses to look at is a rejection.
                    Case(area, id, expected is "invalid" or "acceptable", "rejected", e.GetType().Name);
                }
                catch (Exception e)
                {
                    Case(area, id, false, "exception:" + e.GetType().Name, e.Message);
                }
            }
        }
    }

    private static byte[] Strip(byte[] v)
    {
        int i = 0;
        while (i < v.Length - 1 && v[i] == 0)
        {
            i++;
        }

        return v[i..];
    }

    private static void SshKeys()
    {
        foreach (string name in Fixtures.Keys.Where(n => n.StartsWith("ssh-", StringComparison.Ordinal) && n.EndsWith(".pub", StringComparison.Ordinal)).Order(StringComparer.Ordinal))
        {
            Guard("ssh", name, () =>
            {
                using LoadedItems items = Crypto.Load(Fixtures[name]);
                RecursiveAI.OneCrypto.Wire.Ssh.SshPublicKey k = items.SshPublicKeys[0];
                PublicKeyInfo spki = k.ToPublicKeyInfo();
                return (items.SshPublicKeys.Count == 1, $"{k.Type}|{spki.KeyAlgorithm}|{spki.KeySizeBits}|{Convert.ToHexStringLower(SHA256.HashData(spki.Encoded.Span))[..16]}", "");
            });
        }
    }

    // --- CMS and time-stamps ----------------------------------------------------------------------------------------------

    private static ValidationOptions TrustCa() => new()
    {
        TrustAnchors = [TrustAnchor.FromCertificate(Certificate.FromPem(Encoding.ASCII.GetString(Fixtures["ca-cert.pem"])))],
        ReferenceTime = FixtureTime,
        RequiredExtendedKeyUsage = KnownOids.EmailProtection,
    };

    private static void CmsVerify()
    {
        foreach (string name in Fixtures.Keys.Where(n => n.StartsWith("cms-", StringComparison.Ordinal)).Order(StringComparer.Ordinal))
        {
            Guard("cms", name, () =>
            {
                SignedData sd = SignedData.Parse(Fixtures[name]);
                SignedDataReport report = sd.Verify(new SignedDataVerifyOptions { ReferenceTime = FixtureTime, Chain = TrustCa() });
                string checks = string.Join(",", report.Signers.SelectMany(s => s.Checks).Concat(report.Checks).Select(c => $"{c.Rule}:{c.Status}"));
                bool contentOk = sd.EncapsulatedContent.Span.SequenceEqual(Fixtures["content.txt"]);
                return (report.IsValid && contentOk, (report.IsValid ? "valid|" : "invalid|") + checks, sd.Signers[0].SignatureAlgorithm.Oid);
            });
            Guard("cms", name + " (tampered content)", () =>
            {
                byte[] bytes = (byte[])Fixtures[name].Clone();
                int at = bytes.AsSpan().IndexOf(Fixtures["content.txt"]);
                bytes[at] ^= 1;
                SignedDataReport report = SignedData.Parse(bytes).Verify(new SignedDataVerifyOptions { ReferenceTime = FixtureTime });
                return (!report.IsValid, report.IsValid ? "valid" : "invalid", "");
            });
        }
    }

    private static void TimestampVerify()
    {
        Guard("timestamp", "ts.tsr", () =>
        {
            TimeStampRequest req = TimeStampRequest.Parse(Fixtures["ts.tsq"]);
            TimeStampReport report = TimeStampVerifier.Verify(req, Fixtures["ts.tsr"], new TimeStampVerifyOptions
            {
                ReferenceTime = FixtureTime,
                TrustAnchors = [TrustAnchor.FromCertificate(Certificate.FromPem(Encoding.ASCII.GetString(Fixtures["ca-cert.pem"])))],
            });
            string checks = string.Join(",", report.Checks.Select(c => $"{c.Rule}:{c.Status}"));
            return (report.IsValid, (report.IsValid ? "valid|" : "invalid|") + checks, report.GenTime?.ToString("O", CultureInfo.InvariantCulture) ?? "");
        });
        Guard("timestamp", "ts.tsr (different request)", () =>
        {
            TimeStampRequest req = TimeStampRequest.Create(new TimeStampRequestOptions { Hash = HashAlgorithmName.SHA256, MessageImprint = SHA256.HashData("another"u8) });
            TimeStampReport report = TimeStampVerifier.Verify(req, Fixtures["ts.tsr"]);
            return (!report.IsValid, report.IsValid ? "valid" : "invalid", "");
        });
    }

    // --- path validation --------------------------------------------------------------------------------------------------

    private static void ValidateLimbo(JsonElement root)
    {
        foreach (JsonElement tc in root.GetProperty("limbo").EnumerateArray())
        {
            string id = tc.GetProperty("id").GetString()!;
            string expected = tc.GetProperty("expected_result").GetString()!;
            try
            {
                ValidationOptions o = LimboOptions(tc, out Certificate target);
                ValidationReport r = PathValidator.Validate(target, o);
                string rule = r.DecidingRule is { } d ? d.Rule.ToString() : "-";
                // The native run of this suite is the reference: the verdict here must equal it. Against limbo's own expectation the case
                // passes when the validator agrees or the id is one of the documented deviations (docs/validation.md).
                bool agrees = (expected == "SUCCESS") == r.IsValid;
                bool documented = id is "rfc5280::aki::cross-signed-root-missing-aki" or "webpki::san::public-suffix-multi-label-wildcard-san" or "webpki::san::public-suffix-private-namespace-wildcard-san"
                    || id.StartsWith("rfc9881::", StringComparison.Ordinal);
                Case("validate-limbo", id, agrees || documented, $"{r.Verdict}|{rule}", $"expected {expected}; {r.DecidingRule?.Reason}");
            }
            catch (Exception e) when (e is X509ParseException or FormatException or ArgumentException or KeyNotFoundException or InvalidOperationException)
            {
                // Certificates limbo made to be unparseable are refused with a typed error: no certificate, no path.
                Case("validate-limbo", id, expected == "FAILURE", "ParseRefused", e.GetType().Name);
            }
            catch (Exception e)
            {
                Case("validate-limbo", id, false, "exception:" + e.GetType().Name, e.Message);
            }
        }
    }

    private static ValidationOptions LimboOptions(JsonElement tc, out Certificate target)
    {
        var anchors = new List<TrustAnchor>();
        foreach (JsonElement e in tc.GetProperty("trusted_certs").EnumerateArray())
        {
            anchors.Add(TrustAnchor.FromCertificate(Certificate.FromPem(e.GetString()!)));
        }

        var pool = new List<Certificate>();
        foreach (JsonElement e in tc.GetProperty("untrusted_intermediates").EnumerateArray())
        {
            pool.Add(Certificate.FromPem(e.GetString()!));
        }

        target = Certificate.FromPem(tc.GetProperty("peer_certificate").GetString()!);
        var crls = new List<CertificateRevocationList>();
        if (tc.TryGetProperty("crls", out JsonElement cr))
        {
            foreach (JsonElement e in cr.EnumerateArray())
            {
                crls.Add(CertificateRevocationList.FromPem(e.GetString()!));
            }
        }

        bool server = tc.GetProperty("validation_kind").GetString() == "SERVER";
        string id = tc.GetProperty("id").GetString()!;
        bool webpki = id.StartsWith("webpki::", StringComparison.Ordinal) || id.StartsWith("bettertls::", StringComparison.Ordinal);
        string? name = null;
        if (server && tc.TryGetProperty("expected_peer_name", out JsonElement pn) && pn.ValueKind == JsonValueKind.Object)
        {
            name = pn.GetProperty("value").GetString();
        }

        string? eku = null;
        if (tc.TryGetProperty("extended_key_usage", out JsonElement ek) && ek.GetArrayLength() > 0)
        {
            eku = ek[0].GetString() switch
            {
                "serverAuth" => KnownOids.ServerAuth,
                "clientAuth" => KnownOids.ClientAuth,
                "codeSigning" => KnownOids.CodeSigning,
                "emailProtection" => KnownOids.EmailProtection,
                "timeStamping" => KnownOids.TimeStamping,
                "OCSPSigning" => KnownOids.OcspSigning,
                { } other => other,
                _ => null,
            };
        }

        KeyUsages ku = KeyUsages.None;
        if (tc.TryGetProperty("key_usage", out JsonElement kus))
        {
            foreach (JsonElement k in kus.EnumerateArray())
            {
                ku |= k.GetString() switch
                {
                    "digitalSignature" => KeyUsages.DigitalSignature,
                    "keyCertSign" => KeyUsages.KeyCertSign,
                    "cRLSign" => KeyUsages.CrlSign,
                    "keyEncipherment" => KeyUsages.KeyEncipherment,
                    "keyAgreement" => KeyUsages.KeyAgreement,
                    "contentCommitment" or "nonRepudiation" => KeyUsages.NonRepudiation,
                    _ => KeyUsages.None,
                };
            }
        }

        int? depth = tc.TryGetProperty("max_chain_depth", out JsonElement md) && md.ValueKind == JsonValueKind.Number ? md.GetInt32() : null;
        return new ValidationOptions
        {
            TrustAnchors = anchors,
            Intermediates = pool,
            ReferenceTime = tc.TryGetProperty("validation_time", out JsonElement vt) && vt.ValueKind == JsonValueKind.String
                ? DateTimeOffset.Parse(vt.GetString()!, CultureInfo.InvariantCulture)
                : FixtureTime,
            RequiredExtendedKeyUsage = eku ?? (server ? KnownOids.ServerAuth : KnownOids.ClientAuth),
            RequiredKeyUsage = ku,
            MaxIntermediates = depth,
            // The corpus expects a root with a non-critical or missing basicConstraints, a critical identifier and the like to be refused, which is the
            // opt-in holding an anchor to the CA-certificate rules (the native limbo runner sets it too; the default accepts such roots, RFC 5937 §2).
            StrictAnchorStructure = true,
            Revocation = crls.Count > 0 ? new RevocationData { Crls = crls } : null,
            RevocationRequired = crls.Count > 0 ? RevocationScope.AllCertificates : RevocationScope.None,
            UnknownRevocationIsFatal = crls.Count > 0,
            WebPki = new WebPkiProfile { ServerName = name, RequireServerAuth = server && webpki, EnforceBaselineRequirements = webpki, RequireCommonNameInSan = id.StartsWith("webpki::cn::", StringComparison.Ordinal) },
        };
    }

    // --- where the browser has no primitive -------------------------------------------------------------------------------

    private static void Unsupported()
    {
        // On the browser runtime each of these must fail with the typed error and nothing else; natively it simply works.
        bool browser = OperatingSystem.IsBrowser();
        void Expect(string id, Action act)
        {
            try
            {
                act();
                Case("unsupported", id, !browser, "works", browser ? "the browser runtime has no such primitive but the call succeeded" : "");
            }
            catch (AlgorithmNotSupportedException e)
            {
                Case("unsupported", id, browser && e.Algorithm.Length > 0 && e.Platform.Length > 0, "AlgorithmNotSupported", e.Algorithm);
            }
            catch (Exception e)
            {
                Case("unsupported", id, false, "exception:" + e.GetType().Name, e.Message);
            }
        }

        byte[] key = new byte[16];
        Expect("AES key wrap", () => new AesKeyWrap(key).Dispose());
        Expect("AES-OCB", () => new AesOcb(key).Dispose());
        Expect("AES-EAX", () => new AesEax(key).Dispose());
        Expect("PBES2 decrypt", () => EncryptedPrivateKeyInfo.FromPem(Encoding.ASCII.GetString(Fixtures["pk8-p256-pbes2.pem"])).Decrypt("password"));
        Expect("PKCS#12 open (PBES2)", () => Pkcs12File.Parse(Fixtures["p12-pbes2.p12"]).Open("password"));
        Expect("PKCS#12 open (legacy 3DES)", () => Pkcs12File.Parse(Fixtures["p12-legacy.p12"]).Open("password"));
    }
}
