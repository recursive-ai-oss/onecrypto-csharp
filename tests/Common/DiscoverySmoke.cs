using System.Text;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.OpenPgp;

namespace OneCrypto.Smoke;

/// <summary>
/// Key discovery and Autocrypt in an app that is trimmed or AOT-compiled: the Web Key Directory URL of the draft's example, a replayed directory lookup cut down to
/// the queried address, an HKP index, the Autocrypt example header read, written and used for a peer update and a recommendation, and the example setup message
/// opened with its code. No socket is opened.
/// </summary>
internal static class DiscoverySmoke
{
    // The Autocrypt Level 1 example key (Ed25519 and Cv25519, CC0).
    private const string AliceKey = "mDMEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/Ub7O1u120F2FsaWNlQGF1dG9jcnlwdC5leGFtcGxliJYEExYIAD4WIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCXEcE6QIbAwUJA8JnAAULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRDyMVUMT0fjjkqLAP9frlijwBJvA+HFnqCZcYIVxlyXzS5Gi5gMTpp37K73jgD/VbKYhkwk9iu689OYH4K7q7LbmdeaJ+RX88Y/ad9hZwy4OARcRwTpEgorBgEEAZdVAQUBAQdAQv8GIa2rSTzgqbXCpDDYMiKRVitCsy203x3sE9+eviIDAQgHiHgEGBYIACAWIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCXEcE6QIbDAAKCRDyMVUMT0fjjlnQAQDFHUs6TIcxrNTtEZFjUFm1M0PJ1Dng/cDW4xN80fsn0QEA22Kr7VkCjeAEC08VSTeV+QFsmz55/lntWkwYWhmvOgE=";

    private const string SetupMessage = """
-----BEGIN PGP MESSAGE-----
Passphrase-Format: numeric9x4
Passphrase-Begin: 17

jA0EBwMCFAxADoCdzeX/0ukBlqI5+pfpKb751qd/7nLNbkpy3gVcaf1QwRPZYt40
Ynp08UqRQ2g48ZlnzHLSwlTGOPTuv2Jt8ka+pgZ45xzvJSG2gau03xP4VsC271kR
VmCjdb0Y6Rk96mAwfGzrkbaRQ9Z7fIoL866GOv6h9neiVIkp+JYlTV6ISD0ZQJ4Q
I6dOQkB/TWZyVjtiJDOQHdfNWliA6NtqaLq19wlu9L5xXjuNpY95KwR8EJXWe0+o
Y3d2U/KxOAkXKghP2Qg1GtlPVeGC5T4p03TGI6pzKT+kHX6Rrm9wK6sM9aTquMmF
Vok84Jg1DFnwivWC2RILR81rXi7k/+Y6MUbveFgJ9cQduqpxnmD7TjOblYu7M6zp
YGAUxh8DRKlIMn2QsA++DBYQ6ACZvwuY8qTDLkqPDo4WqM313dsMJbyGjDdVE7EM
PESS+RlABETpZXz8g/ycr6DIUNdlbPcmYlsBfHWDOuR2GFFTwmlv5slWS39dJv38
E0eIe1CwdxI801Se7t7dUUS/ZF8wb6GlmxOcqGbF8eko1Z0S64IAm7/h13MRQCxI
geQnHfGYVJ2FOimoCMEKwfa9x++RFTDW0u7spDC2uWvK/1viV8OfRppFhLr/kmKb
18lWXuAz80DAjUDUsVqEq2MvJBJGoCJUEyjuRsLkHYRM5jYk4v50LyyR0Om73nWF
nZBqmqNzdr7Xb9PHHdFhnEc0VvoYbrcM0RVYcEMW3YbmejM891j1d6Iv+/n/qND/
NdebGrfWJMmFLf/iEkzTZ3/v5inW9LpWoRc94ioCjJTaEo8Rib6ARRFaJVIsmNXi
YicFGO98D+zX+a2t9Yz6IpPajVslnOp6ScpmXgts/2XWD7oE+JgxSAqo/dLVsHgP
Ufo=
=pulM
-----END PGP MESSAGE-----
""";

    public static async Task<bool> Run()
    {
        var now = new DateTimeOffset(2019, 1, 23, 12, 0, 0, TimeSpan.Zero);
        byte[] key = Convert.FromBase64String(AliceKey);

        WkdAddress address = WkdAddress.Parse("Joe.Doe@Example.ORG");
        bool wkd = address.Hash == "iy9q119eutrkn8s1mk4r39qejnbu3n5q";

        var log = new ExchangeLog();
        Uri uri = WkdAddress.Parse("alice@autocrypt.example").KeyUri(WkdMethod.Advanced);
        log.Exchanges.Add(new RecordedExchange { Method = "GET", Uri = uri.AbsoluteUri, Status = 200, Body = key });
        var replay = new ReplayTransport(ExchangeLog.Parse(log.ToJson()));
        WkdLookupResult found = await new WkdClient(new Fetcher(replay, new FetchOptions { Cache = null })).LookupAsync("alice@autocrypt.example");
        DiscoveredKeys keys = KeyDiscovery.ForAddress(found.Body, "alice@autocrypt.example");
        bool lookup = found.IsSuccess && keys.Certificates.Count == 1 && replay.Requests.Count == 1;

        bool index = HkpIndex.TryParse("info:1:1\npub:ABCDEF0123456789ABCDEF0123456789ABCDEF01:22:256:1500000000::\nuid:Alice%20%3Calice%40example.org%3E:::\n"u8, out HkpIndex? parsed)
            && parsed!.Entries.Count == 1 && parsed.Entries[0].UserIds[0].Text == "Alice <alice@example.org>";

        var header = AutocryptHeader.Create("alice@autocrypt.example", PgpCertificate.Parse(key), AutocryptPreference.Mutual);
        AutocryptHeader again = AutocryptHeader.Parse(header.ToHeaderValue());
        AutocryptUpdate update = AutocryptPeer.Apply(null, new AutocryptMessage { FromAddress = "alice@autocrypt.example", Date = now.AddDays(-1), Received = now, AutocryptHeaders = [header.ToHeaderValue()] });
        AutocryptMessageRecommendation recommend = AutocryptRecommender.Recommend(["alice@autocrypt.example"], new Dictionary<string, AutocryptPeer> { [update.Peer.Address] = update.Peer }, new AutocryptComposeContext { Now = now, OwnPreference = AutocryptPreference.Mutual });
        bool autocrypt = again.Address == header.Address && update.Changed && recommend.Recommendation == AutocryptRecommendation.Encrypt;

        AutocryptSetupResult setup = AutocryptSetupMessage.Open(Encoding.ASCII.GetBytes(SetupMessage), "1742-0185-6197-1303-7016-8412-3581-4441-0597", now);
        bool opened = setup.IsSuccess && setup.Content!.Certificate.HasSecretKeyMaterial && setup.Content.PreferEncrypt == AutocryptPreference.Mutual;

        Console.WriteLine($"discovery: wkd hash {wkd}, lookup {lookup}, index {index}, autocrypt {autocrypt} ({recommend.Recommendation}), setup message {setup.Outcome}");
        return wkd && lookup && index && autocrypt && opened;
    }
}
