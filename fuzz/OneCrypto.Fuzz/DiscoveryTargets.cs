using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.OpenPgp;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace OneCrypto.Fuzz;

/// <summary>
/// Autocrypt (<c>autocrypt</c>). The first byte picks the surface: a header value (a header that parses must write back to a header that parses to the same
/// address, preference and key, and be valid as gossip), a peer update fed the text as the message's header together with a second, mutated one, the
/// recommendation over a peer built from the text, or a setup message opened with the specification's code. Nothing but a typed result may come out.
/// </summary>
internal static class AutocryptTarget
{
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 1)
        {
            return;
        }

        byte pick = data[0];
        ReadOnlySpan<byte> rest = data[1..];
        switch (pick % 4)
        {
            case 0:
                Header(Encoding.UTF8.GetString(rest));
                break;
            case 1:
            {
                string text = Encoding.UTF8.GetString(rest);
                int cut = text.Length / 2;
                AutocryptUpdate u = AutocryptPeer.Apply(null, new AutocryptMessage { FromAddress = "alice@autocrypt.example", Date = Now.AddDays(-1), Received = Now, AutocryptHeaders = [text, text[..cut]] });
                _ = AutocryptPeer.Apply(u.Peer, new AutocryptMessage { FromAddress = "alice@autocrypt.example", Date = Now.AddDays(-2), Received = Now, AutocryptHeaders = [text] });
                _ = AutocryptPeer.ApplyGossip(u.Peer, text, new AutocryptGossipContext { RecipientAddresses = ["alice@autocrypt.example"], Received = Now });
                break;
            }

            case 2:
            {
                var peer = new AutocryptPeer { Address = "x@example.org", LastSeen = Now, AutocryptTimestamp = Now.AddDays(-pick), PublicKey = rest.ToArray(), GossipKey = rest.ToArray(), PreferEncrypt = (AutocryptPreference)(pick & 1) };
                _ = AutocryptRecommender.Recommend(["x@example.org", "y@example.org"], new Dictionary<string, AutocryptPeer> { ["x@example.org"] = peer }, new AutocryptComposeContext { Now = Now });
                break;
            }

            default:
                _ = AutocryptSetupMessage.ReadHints(rest.ToArray());
                AutocryptSetupResult r = AutocryptSetupMessage.Open(rest.ToArray(), "1742-0185-6197-1303-7016-8412-3581-4441-0597", Now);
                if (r.IsSuccess && r.Content is null)
                {
                    throw new InvalidOperationException("an opened setup message must carry its content");
                }

                break;
        }
    }

    private static void Header(string text)
    {
        if (!AutocryptHeader.TryParse(text, out AutocryptHeader? h, out AutocryptHeaderError error))
        {
            if (h is not null || error == AutocryptHeaderError.None)
            {
                throw new InvalidOperationException("a header that fails must say why and carry nothing");
            }

            return;
        }

        string again = h!.ToHeaderValue();
        if (!AutocryptHeader.TryParse(again, out AutocryptHeader? h2, out _) || h2!.Address != h.Address || h2.PreferEncrypt != h.PreferEncrypt || !h2.KeyData.AsSpan().SequenceEqual(h.KeyData))
        {
            throw new InvalidOperationException("a header that parses must write back to the same header");
        }

        if (!AutocryptHeader.TryParse(h.AsGossip().ToHeaderValue(), out _, out _))
        {
            throw new InvalidOperationException("a header that parses must be valid as gossip too");
        }
    }

    public static IEnumerable<byte[]> Seeds()
    {
        string dir = Path.Combine(Path.GetDirectoryName(ThisFile())!, "..", "..", "testdata", "openpgp", "autocrypt");
        if (!Directory.Exists(dir))
        {
            yield break;
        }

        byte[] value = File.ReadAllBytes(Path.Combine(dir, "alice-header-value.txt"));
        yield return [0, .. value];
        yield return [1, .. value];
        yield return [2, .. AutocryptHeader.Parse(Encoding.UTF8.GetString(value)).KeyData];
        yield return [3, .. File.ReadAllBytes(Path.Combine(dir, "setup-message.asc"))];
        yield return [0, .. "addr=a@example.org; prefer-encrypt=mutual; _x=1; keydata=AAAA"u8.ToArray()];
    }

    private static string ThisFile([CallerFilePath] string path = "") => path;
}

/// <summary>
/// Discovery responses (<c>hkpindex</c>). The first byte picks the surface: an HKP machine-readable index, a Web Key Directory policy file and address,
/// or the bytes of a key response given to the certificate filter (by address, by key, and unfiltered). Only typed results may come out: the index and the
/// filter never throw for hostile bytes, and everything they keep must obey their documented bounds.
/// </summary>
internal static class DiscoveryTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 1)
        {
            return;
        }

        ReadOnlySpan<byte> rest = data[1..];
        switch (data[0] % 3)
        {
            case 0:
                Index(rest);
                break;
            case 1:
            {
                string text = Encoding.UTF8.GetString(rest);
                WkdPolicy p = WkdPolicy.Parse(text);
                _ = p.ProtocolVersion;
                _ = p.SubmissionAddress;
                if (WkdAddress.TryParse(text, out WkdAddress? a))
                {
                    if (a!.Hash.Length != 32 || !a.KeyUri(WkdMethod.Advanced).IsAbsoluteUri || !a.KeyUri(WkdMethod.Direct).IsAbsoluteUri)
                    {
                        throw new InvalidOperationException("an accepted address must give two absolute URLs and a 32 character hash");
                    }
                }

                _ = HkpServer.TryParse(text, out _);
                break;
            }

            default:
            {
                byte[] bytes = rest.ToArray();
                DiscoveredKeys d = KeyDiscovery.ForAddress(bytes, "dkg@fifthhorseman.net");
                foreach (PgpCertificate c in d.Certificates)
                {
                    if (c.HasSecretKeyMaterial || !c.UserIds.Any())
                    {
                        throw new InvalidOperationException("an address lookup must keep public certificates with the queried User ID");
                    }
                }

                _ = KeyDiscovery.ForKey(bytes, new byte[8]);
                if (KeyDiscovery.ReadAll(bytes, new DiscoveryOptions { MaxCertificates = 4 }).Certificates.Count > 4)
                {
                    throw new InvalidOperationException("the certificate cap was exceeded");
                }

                break;
            }
        }
    }

    private static void Index(ReadOnlySpan<byte> bytes)
    {
        if (!HkpIndex.TryParse(bytes, out HkpIndex? i))
        {
            return;
        }

        if (i!.Entries.Count > HkpIndex.MaxEntries || i.Entries.Any(e => e.UserIds.Count > HkpIndex.MaxUserIdsPerEntry || e.KeyId.Length == 0))
        {
            throw new InvalidOperationException("the index bounds were exceeded");
        }

        _ = HkpIndex.Parse(bytes);
    }

    public static IEnumerable<byte[]> Seeds()
    {
        yield return [0, .. "info:1:1\npub:ABCDEF0123456789ABCDEF0123456789ABCDEF01:22:256:1500000000:1600000000:r\nuid:Alice%20%3Calice%40example.org%3E:1500000001::\n"u8.ToArray()];
        yield return [1, .. "# policy\nmailbox-only\nprotocol-version: 3\nsubmission-address: key-submission@example.org\n"u8.ToArray()];
        yield return [1, .. "Joe.Doe@Example.ORG"u8.ToArray()];
        string online = Path.Combine(Path.GetDirectoryName(ThisFile())!, "..", "..", "testdata", "openpgp", "autocrypt");
        if (Directory.Exists(online))
        {
            yield return [2, .. File.ReadAllBytes(Path.Combine(online, "setup-key.asc"))];
            yield return [2, .. Convert.FromBase64String(string.Concat(File.ReadAllLines(Path.Combine(online, "alice-header-value.txt")).Skip(1).Select(l => l.Trim())))];
        }
    }

    private static string ThisFile([CallerFilePath] string path = "") => path;
}
