using System.Diagnostics;
using System.Text;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>Autocrypt Level 1: header values, peer state, the recommendation and the setup message, against the specification's own examples.</summary>
public class AutocryptTests
{
    private const string AliceFingerprint = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";

    private static readonly DateTimeOffset T0 = new(2019, 1, 22, 12, 0, 0, TimeSpan.Zero);

    private static string AliceValue => File.ReadAllText(TestFiles.OpenPgp("autocrypt", "alice-header-value.txt"));

    private static string SetupCode => File.ReadAllText(TestFiles.OpenPgp("autocrypt", "setup-code.txt")).Trim();

    private static byte[] SetupMessage => File.ReadAllBytes(TestFiles.OpenPgp("autocrypt", "setup-message.asc"));

    private static byte[] AliceKey => AutocryptHeader.Parse(AliceValue).KeyData;

    // ---- the header

    [Fact]
    public void TheSpecificationsExampleHeaderParses()
    {
        AutocryptHeader h = AutocryptHeader.Parse(AliceValue);
        Assert.Equal("alice@autocrypt.example", h.Address);
        Assert.Equal(AutocryptPreference.Mutual, h.PreferEncrypt);
        Assert.Equal(AliceFingerprint, Convert.ToHexString(h.Certificate.Fingerprint));
        Assert.Equal(["alice@autocrypt.example"], h.Certificate.UserIds.ToArray());
        Assert.True(h.IsValidFor("Alice@Autocrypt.Example"));
        Assert.False(h.IsValidFor("bob@autocrypt.example"));
    }

    [Fact]
    public void AWrittenHeaderParsesBackToTheSameKeyAndStaysUnderTheLimit()
    {
        AutocryptHeader h = AutocryptHeader.Parse(AliceValue);
        foreach (AutocryptPreference p in new[] { AutocryptPreference.Mutual, AutocryptPreference.NoPreference })
        {
            AutocryptHeader made = AutocryptHeader.Create("alice@autocrypt.example", h.Certificate, p);
            string field = made.ToHeaderField();
            Assert.StartsWith("Autocrypt: addr=alice@autocrypt.example; ", field, StringComparison.Ordinal);
            Assert.Equal(p == AutocryptPreference.Mutual, field.Contains("prefer-encrypt=mutual", StringComparison.Ordinal));
            Assert.True(field.Length < AutocryptHeader.MaxHeaderLength);
            Assert.All(field.Split("\r\n"), l => Assert.True(l.Length <= 78));
            AutocryptHeader again = AutocryptHeader.Parse(field["Autocrypt:".Length..]);
            Assert.Equal(h.KeyData, again.KeyData);
            Assert.Equal(p, again.PreferEncrypt);
        }

        Assert.Equal(AutocryptPreference.NoPreference, AutocryptHeader.Parse(AliceValue).AsGossip().PreferEncrypt);
    }

    [Theory]
    [InlineData("", AutocryptHeaderError.Empty)]
    [InlineData("   ", AutocryptHeaderError.Empty)]
    [InlineData("prefer-encrypt=mutual; keydata=AAAA", AutocryptHeaderError.MissingAddr)]
    [InlineData("addr=a@example.org", AutocryptHeaderError.MissingKeyData)]
    [InlineData("addr=a@example.org; keydata=", AutocryptHeaderError.MissingKeyData)]
    [InlineData("addr=not-an-address; keydata=AAAA", AutocryptHeaderError.InvalidAddr)]
    [InlineData("addr=a@example.org; addr=b@example.org; keydata=AAAA", AutocryptHeaderError.DuplicateAttribute)]
    [InlineData("addr=a@example.org; new-thing=1; keydata=AAAA", AutocryptHeaderError.UnsupportedCriticalAttribute)]
    [InlineData("addr=a@example.org; keydata=!!!!", AutocryptHeaderError.InvalidKeyData)]
    [InlineData("addr=a@example.org; keydata=AAAA", AutocryptHeaderError.InvalidKeyData)]
    [InlineData("addr=a@example.org keydata=AAAA", AutocryptHeaderError.InvalidAddr)]
    [InlineData("garbage", AutocryptHeaderError.Malformed)]
    public void InvalidHeadersSayWhy(string value, AutocryptHeaderError expected)
    {
        Assert.False(AutocryptHeader.TryParse(value, out AutocryptHeader? h, out AutocryptHeaderError e));
        Assert.Null(h);
        Assert.Equal(expected, e);
        Assert.Equal(expected, Assert.Throws<AutocryptFormatException>(() => AutocryptHeader.Parse(value)).Error);
    }

    [Fact]
    public void UnknownNonCriticalAttributesAreIgnoredAndOddPreferencesMeanNone()
    {
        string v = "addr=alice@autocrypt.example; _future=whatever; prefer-encrypt=sometimes; keydata=" + Convert.ToBase64String(AliceKey);
        AutocryptHeader h = AutocryptHeader.Parse(v);
        Assert.Equal(AutocryptPreference.NoPreference, h.PreferEncrypt);
        Assert.Equal(AliceKey, h.KeyData);
    }

    [Fact]
    public void FoldedWhiteSpaceInTheKeyDataIsTolerated()
    {
        string b64 = Convert.ToBase64String(AliceKey);
        string folded = string.Join("\r\n ", Enumerable.Range(0, (b64.Length + 39) / 40).Select(i => b64.Substring(i * 40, Math.Min(40, b64.Length - (i * 40)))));
        Assert.Equal(AliceKey, AutocryptHeader.Parse("addr=alice@autocrypt.example;\r\n keydata=\r\n " + folded).KeyData);
    }

    [Fact]
    public void OversizeHeadersAreInvalidAndSecretOrMultipleKeysAreRefused()
    {
        string big = "addr=a@example.org; keydata=" + new string('A', AutocryptHeader.MaxHeaderLength);
        Assert.False(AutocryptHeader.TryParse(big, out _, out AutocryptHeaderError e));
        Assert.Equal(AutocryptHeaderError.TooLarge, e);

        byte[] secret = Armor.Decode(File.ReadAllBytes(TestFiles.OpenPgp("autocrypt", "setup-key.asc"))).Data;
        Assert.False(AutocryptHeader.TryParse("addr=alice@autocrypt.example; keydata=" + Convert.ToBase64String(secret), out _, out e));
        Assert.Equal(AutocryptHeaderError.KeyNotSinglePublicCertificate, e);

        Assert.False(AutocryptHeader.TryParse("addr=alice@autocrypt.example; keydata=" + Convert.ToBase64String([.. AliceKey, .. AliceKey]), out _, out e));
        Assert.Equal(AutocryptHeaderError.KeyNotSinglePublicCertificate, e);

        // Armored key data is not binary key data.
        Assert.False(AutocryptHeader.TryParse("addr=a@example.org; keydata=" + Convert.ToBase64String(File.ReadAllBytes(TestFiles.OpenPgp("autocrypt", "setup-key.asc"))), out _, out e));
        Assert.Equal(AutocryptHeaderError.InvalidKeyData, e);
    }

    // ---- peer state

    private static string Header(string addr = "alice@autocrypt.example", bool mutual = false) =>
        $"addr={addr}; {(mutual ? "prefer-encrypt=mutual; " : string.Empty)}keydata={Convert.ToBase64String(AliceKey)}";

    private static AutocryptMessage Msg(DateTimeOffset date, DateTimeOffset? received = null, string from = "Alice@autocrypt.example", params string[] headers) =>
        new() { FromAddress = from, Date = date, Received = received ?? date, AutocryptHeaders = headers };

    [Fact]
    public void AMessageWithAValidHeaderSetsTheKeyAndTheDates()
    {
        AutocryptUpdate u = AutocryptPeer.Apply(null, Msg(T0, null, "Alice@autocrypt.example", Header(mutual: true)));
        Assert.True(u.Changed);
        Assert.Equal("alice@autocrypt.example", u.Peer.Address);
        Assert.Equal(T0, u.Peer.LastSeen);
        Assert.Equal(T0, u.Peer.AutocryptTimestamp);
        Assert.Equal(AliceKey, u.Peer.PublicKey);
        Assert.Equal(AutocryptPreference.Mutual, u.Peer.PreferEncrypt);
    }

    [Fact]
    public void AMessageWithoutAHeaderOnlyMovesLastSeen()
    {
        AutocryptPeer p = AutocryptPeer.Apply(null, Msg(T0, null, "alice@autocrypt.example", Header())).Peer;
        AutocryptUpdate u = AutocryptPeer.Apply(p, Msg(T0.AddDays(3)));
        Assert.Equal(T0.AddDays(3), u.Peer.LastSeen);
        Assert.Equal(T0, u.Peer.AutocryptTimestamp);
        Assert.Equal(AliceKey, u.Peer.PublicKey);
        Assert.Contains("no valid", u.Note, StringComparison.Ordinal);
    }

    [Fact]
    public void OlderMessagesChangeNothingAndFutureDatesAreClampedToReceipt()
    {
        AutocryptPeer p = AutocryptPeer.Apply(null, Msg(T0, null, "alice@autocrypt.example", Header(mutual: true))).Peer;
        AutocryptUpdate old = AutocryptPeer.Apply(p, Msg(T0.AddDays(-1), null, "alice@autocrypt.example", Header()));
        Assert.False(old.Changed);
        Assert.Same(p, old.Peer);

        var future = new AutocryptMessage { FromAddress = "alice@autocrypt.example", Date = T0.AddYears(10), Received = T0.AddDays(2), AutocryptHeaders = [Header()] };
        Assert.Equal(T0.AddDays(2), future.EffectiveDate);
        AutocryptUpdate u = AutocryptPeer.Apply(p, future);
        Assert.Equal(T0.AddDays(2), u.Peer.AutocryptTimestamp);
        Assert.Equal(AutocryptPreference.NoPreference, u.Peer.PreferEncrypt);

        Assert.Equal(T0.AddDays(5), new AutocryptMessage { FromAddress = "a@example.org", Received = T0.AddDays(5) }.EffectiveDate);
    }

    [Fact]
    public void HeadersForAnotherAddressTwoValidHeadersOrIgnoredMessagesDoNotUpdateTheKey()
    {
        AutocryptUpdate wrong = AutocryptPeer.Apply(null, Msg(T0, null, "mallory@example.org", Header()));
        Assert.Null(wrong.Peer.PublicKey);
        Assert.Equal(T0, wrong.Peer.LastSeen);
        Assert.Contains(AutocryptHeaderError.AddressMismatch, wrong.HeaderErrors);

        AutocryptUpdate two = AutocryptPeer.Apply(null, Msg(T0, null, "alice@autocrypt.example", Header(), Header(mutual: true)));
        Assert.Null(two.Peer.PublicKey);
        Assert.Contains("more than one", two.Note, StringComparison.Ordinal);

        // One valid and one broken header: the valid one counts.
        Assert.NotNull(AutocryptPeer.Apply(null, Msg(T0, null, "alice@autocrypt.example", Header(), "addr=alice@autocrypt.example; keydata=!!")).Peer.PublicKey);

        foreach (AutocryptMessage m in new[]
        {
            new AutocryptMessage { FromAddress = "alice@autocrypt.example", Received = T0, AutocryptHeaders = [Header()], IsAutoGeneratedReport = true },
            new AutocryptMessage { FromAddress = "alice@autocrypt.example", Received = T0, AutocryptHeaders = [Header()], FromAddressCount = 2 },
            new AutocryptMessage { FromAddress = "alice@autocrypt.example", Received = T0, AutocryptHeaders = [Header()], IsSpam = true },
        })
        {
            AutocryptUpdate u = AutocryptPeer.Apply(null, m);
            Assert.False(u.Changed);
            Assert.Null(u.Peer.LastSeen);
        }
    }

    [Fact]
    public void GossipUpdatesOnlyAddressedPeersAndNeverGoesBackwards()
    {
        var ctx = new AutocryptGossipContext { RecipientAddresses = ["bob@autocrypt.example", "Alice@autocrypt.example"], Received = T0 };
        AutocryptUpdate u = AutocryptPeer.ApplyGossip(null, Header(), ctx);
        Assert.True(u.Changed);
        Assert.Equal(AliceKey, u.Peer.GossipKey);
        Assert.Equal(T0, u.Peer.GossipTimestamp);
        Assert.Null(u.Peer.PublicKey);

        Assert.False(AutocryptPeer.ApplyGossip(null, Header(), new AutocryptGossipContext { RecipientAddresses = ["bob@autocrypt.example"], Received = T0 }).Changed);
        Assert.False(AutocryptPeer.ApplyGossip(u.Peer, Header(), new AutocryptGossipContext { RecipientAddresses = ["alice@autocrypt.example"], Received = T0.AddDays(-1) }).Changed);
        Assert.False(AutocryptPeer.ApplyGossip(null, "addr=alice@autocrypt.example; keydata=!!", ctx).Changed);
    }

    // ---- the recommendation

    private static AutocryptComposeContext Ctx(DateTimeOffset? now = null, bool mutual = false, bool reply = false) =>
        new() { Now = now ?? T0.AddDays(1), OwnPreference = mutual ? AutocryptPreference.Mutual : AutocryptPreference.NoPreference, IsReplyToEncrypted = reply, IsKeyUsable = (_, _) => true };

    private static AutocryptPeer Peer(string addr, DateTimeOffset? seen = null, DateTimeOffset? autocrypt = null, bool mutual = false, bool gossip = false) => new()
    {
        Address = addr,
        LastSeen = seen,
        AutocryptTimestamp = autocrypt,
        PublicKey = autocrypt is null ? null : [1],
        PreferEncrypt = mutual ? AutocryptPreference.Mutual : AutocryptPreference.NoPreference,
        GossipKey = gossip ? [2] : null,
        GossipTimestamp = gossip ? T0 : null,
    };

    private static AutocryptRecommendation One(AutocryptPeer? peer, AutocryptComposeContext ctx) => AutocryptRecommender.ForPeer("x@example.org", peer, ctx).Recommendation;

    [Fact]
    public void SingleRecipientRecommendationFollowsTheAlgorithm()
    {
        Assert.Equal(AutocryptRecommendation.Disable, One(null, Ctx()));
        Assert.Equal(AutocryptRecommendation.Disable, One(Peer("x@example.org", T0), Ctx()));
        Assert.Equal(AutocryptRecommendation.Available, One(Peer("x@example.org", T0, T0), Ctx()));

        // Exactly 35 days is still current; one second more is stale.
        Assert.Equal(AutocryptRecommendation.Available, One(Peer("x@example.org", T0.AddDays(35), T0), Ctx()));
        Assert.Equal(AutocryptRecommendation.Discourage, One(Peer("x@example.org", T0.AddDays(35).AddSeconds(1), T0), Ctx()));

        // Gossip alone is only ever a discouraged key.
        Assert.Equal(AutocryptRecommendation.Discourage, One(Peer("x@example.org", T0, null, false, true), Ctx()));

        // Mutual on both sides turns encryption on, one side does not.
        Assert.Equal(AutocryptRecommendation.Encrypt, One(Peer("x@example.org", T0, T0, true), Ctx(mutual: true)));
        Assert.Equal(AutocryptRecommendation.Available, One(Peer("x@example.org", T0, T0, true), Ctx(mutual: false)));
        Assert.Equal(AutocryptRecommendation.Available, One(Peer("x@example.org", T0, T0, false), Ctx(mutual: true)));
        Assert.Equal(AutocryptRecommendation.Discourage, One(Peer("x@example.org", T0.AddDays(40), T0, true), Ctx(mutual: true)));

        // A reply to an encrypted message encrypts, even with a stale or gossiped key, but never with no key.
        Assert.Equal(AutocryptRecommendation.Encrypt, One(Peer("x@example.org", T0.AddDays(40), T0), Ctx(reply: true)));
        Assert.Equal(AutocryptRecommendation.Encrypt, One(Peer("x@example.org", T0, null, false, true), Ctx(reply: true)));
        Assert.Equal(AutocryptRecommendation.Disable, One(null, Ctx(reply: true)));
    }

    [Fact]
    public void AnUnusableKeyCountsAsAbsent()
    {
        AutocryptComposeContext none = new() { Now = T0, IsKeyUsable = (_, _) => false };
        Assert.Equal(AutocryptRecommendation.Disable, One(Peer("x@example.org", T0, T0, false, true), none));

        // Only the gossip key works: it is the target, and the answer is discourage.
        AutocryptComposeContext gossipOnly = new() { Now = T0, IsKeyUsable = (k, _) => k[0] == 2 };
        AutocryptRecipientRecommendation r = AutocryptRecommender.ForPeer("x@example.org", Peer("x@example.org", T0, T0, false, true), gossipOnly);
        Assert.Equal(AutocryptRecommendation.Discourage, r.Recommendation);
        Assert.Equal([2], r.TargetKey);
    }

    [Fact]
    public void AMessageToSeveralRecipientsTakesTheWorstOrTheUnanimousEncrypt()
    {
        var peers = new Dictionary<string, AutocryptPeer>
        {
            ["a@example.org"] = Peer("a@example.org", T0, T0, true),
            ["b@example.org"] = Peer("b@example.org", T0, T0, true),
            ["c@example.org"] = Peer("c@example.org", T0, T0, false),
            ["d@example.org"] = Peer("d@example.org", T0.AddDays(50), T0, false),
        };
        AutocryptComposeContext ctx = Ctx(mutual: true);
        Assert.Equal(AutocryptRecommendation.Encrypt, AutocryptRecommender.Recommend(["A@example.org", "b@example.org"], peers, ctx).Recommendation);
        Assert.Equal(AutocryptRecommendation.Available, AutocryptRecommender.Recommend(["a@example.org", "c@example.org"], peers, ctx).Recommendation);
        Assert.Equal(AutocryptRecommendation.Discourage, AutocryptRecommender.Recommend(["a@example.org", "c@example.org", "d@example.org"], peers, ctx).Recommendation);
        AutocryptMessageRecommendation withUnknown = AutocryptRecommender.Recommend(["a@example.org", "stranger@example.org"], peers, ctx);
        Assert.Equal(AutocryptRecommendation.Disable, withUnknown.Recommendation);
        Assert.Equal(["a@example.org"], withUnknown.TargetKeys.Keys.ToArray());
        Assert.Equal(AutocryptRecommendation.Disable, AutocryptRecommender.Recommend([], peers, ctx).Recommendation);
    }

    [Fact]
    public void KeyUsabilityUsesTheCertificateAtTheGivenTime()
    {
        Assert.True(AutocryptRecommender.CanEncrypt(AliceKey, T0));
        Assert.False(AutocryptRecommender.CanEncrypt(AliceKey, T0.AddYears(-5)));
        Assert.False(AutocryptRecommender.CanEncrypt([1, 2, 3], T0));
        var peer = new AutocryptPeer { Address = "alice@autocrypt.example", LastSeen = T0, AutocryptTimestamp = T0, PublicKey = AliceKey };
        Assert.Equal(AutocryptRecommendation.Available, AutocryptRecommender.ForPeer("alice@autocrypt.example", peer, new AutocryptComposeContext { Now = T0 }).Recommendation);
        Assert.Equal(AutocryptRecommendation.Disable, AutocryptRecommender.ForPeer("alice@autocrypt.example", peer, new AutocryptComposeContext { Now = T0.AddYears(-5) }).Recommendation);
    }

    // ---- the setup message

    [Fact]
    public void TheSpecificationsSetupMessageOpensWithItsCode()
    {
        AutocryptSetupResult r = AutocryptSetupMessage.Open(SetupMessage, SetupCode, T0);
        Assert.True(r.IsSuccess, r.Reason);
        Assert.Equal(AutocryptPreference.Mutual, r.Content!.PreferEncrypt);
        Assert.True(r.Content.Certificate.HasSecretKeyMaterial);
        Assert.Equal(AliceFingerprint, Convert.ToHexString(r.Content.Certificate.Fingerprint));
        Assert.Equal((string?)"numeric9x4", AutocryptSetupMessage.ReadHints(SetupMessage).Format);
        Assert.Equal("17", AutocryptSetupMessage.ReadHints(SetupMessage).Begin);
    }

    [Fact]
    public void TheCodeIsAcceptedAsTypedAndInsideOtherText()
    {
        string typed = SetupCode.Replace("-", " ", StringComparison.Ordinal);
        Assert.True(AutocryptSetupMessage.Open(SetupMessage, typed, T0).IsSuccess);
        Assert.True(AutocryptSetupMessage.Open(SetupMessage, SetupCode.Replace("-", string.Empty, StringComparison.Ordinal), T0).IsSuccess);

        string wrapped = "<html><body><p>This is the Autocrypt setup file.</p><pre>\n" + Encoding.ASCII.GetString(SetupMessage) + "</pre></body></html>\n";
        Assert.True(AutocryptSetupMessage.Open(Encoding.ASCII.GetBytes(wrapped), SetupCode, T0).IsSuccess);
        Assert.Equal("17", AutocryptSetupMessage.ReadHints(Encoding.ASCII.GetBytes(wrapped)).Begin);
    }

    [Fact]
    public void AWrongCodeOrAnAlteredMessageOpensNothing()
    {
        string wrong = "1742-0185-6197-1303-7016-8412-3581-4441-0598";
        AutocryptSetupResult r = AutocryptSetupMessage.Open(SetupMessage, wrong, T0);
        Assert.Equal(AutocryptSetupOutcome.WrongCodeOrCorrupt, r.Outcome);
        Assert.Null(r.Content);
        Assert.Equal(AutocryptSetupOutcome.WrongCodeOrCorrupt, AutocryptSetupMessage.Open(SetupMessage, string.Empty, T0).Outcome);

        // Flip a bit in the body of the encrypted data: the integrity check fails, with the right code.
        ArmorBlock block = Armor.Decode(SetupMessage);
        byte[] data = (byte[])block.Data.Clone();
        data[^5] ^= 0x01;
        string altered = Armor.Encode(ArmorKind.Message, data);
        Assert.Equal(AutocryptSetupOutcome.WrongCodeOrCorrupt, AutocryptSetupMessage.Open(Encoding.ASCII.GetBytes(altered), SetupCode, T0).Outcome);
    }

    [Fact]
    public void NonSetupMessagesAreReportedAsSuch()
    {
        Assert.Equal(AutocryptSetupOutcome.NotASetupMessage, AutocryptSetupMessage.Open("hello"u8.ToArray(), SetupCode, T0).Outcome);
        Assert.Equal(AutocryptSetupOutcome.NotASetupMessage, AutocryptSetupMessage.Open(File.ReadAllBytes(TestFiles.OpenPgp("autocrypt", "setup-key.asc")), SetupCode, T0).Outcome);
        Assert.Equal((null, null), AutocryptSetupMessage.ReadHints("hello"u8.ToArray()));

        // A public-key encrypted message (the gossip example) is not a password message: the code opens nothing.
        Assert.NotEqual(AutocryptSetupOutcome.Opened, AutocryptSetupMessage.Open(File.ReadAllBytes(TestFiles.OpenPgp("autocrypt", "gossip-message.asc")), SetupCode, T0).Outcome);
        Assert.Equal(AutocryptSetupOutcome.TooLarge, AutocryptSetupMessage.Open(new byte[(4 << 20) + 1], SetupCode, T0).Outcome);
    }

    [Fact]
    public void ASetupMessageMadeHereOpensAndCarriesTheHints()
    {
        PgpCertificate secret = AutocryptSetupMessage.Open(SetupMessage, SetupCode, T0).Content!.Certificate;
        string code = AutocryptSetupMessage.GenerateSetupCode();
        Assert.Matches("^[0-9]{4}(-[0-9]{4}){8}$", code);
        Assert.NotEqual(code, AutocryptSetupMessage.GenerateSetupCode());

        foreach (AutocryptPreference p in new[] { AutocryptPreference.Mutual, AutocryptPreference.NoPreference })
        {
            string message = AutocryptSetupMessage.Create(secret, code, p, T0);
            Assert.StartsWith("-----BEGIN PGP MESSAGE-----\nPassphrase-Format: numeric9x4\nPassphrase-Begin: " + code[..2] + "\n", message.Replace("\r\n", "\n", StringComparison.Ordinal), StringComparison.Ordinal);
            AutocryptSetupResult r = AutocryptSetupMessage.Open(Encoding.ASCII.GetBytes(message), code, T0);
            Assert.True(r.IsSuccess, r.Reason);
            Assert.Equal(p, r.Content!.PreferEncrypt);
            Assert.Equal(secret.Fingerprint, r.Content.Certificate.Fingerprint);
            Assert.Equal(AutocryptSetupOutcome.WrongCodeOrCorrupt, AutocryptSetupMessage.Open(Encoding.ASCII.GetBytes(message), AutocryptSetupMessage.GenerateSetupCode(), T0).Outcome);

            // Level 1: the message is a password session key packet followed by an integrity-protected data packet.
            Packets.Packet[] packets = [.. Packets.PacketParser.ParseAll(Armor.Decode(Encoding.ASCII.GetBytes(message)).Data)];
            Assert.Equal([(byte)Packets.PacketTag.SymmetricKeyEncryptedSessionKey, (byte)Packets.PacketTag.SymmetricallyEncryptedIntegrityProtectedData], packets.Select(x => x.TagId).ToArray());
            Assert.Equal(4, packets[0].Body.Span[0]);
            Assert.Equal(1, packets[1].Body.Span[0]);
        }

        Assert.Throws<ArgumentException>(() => AutocryptSetupMessage.Create(AutocryptHeader.Parse(AliceValue).Certificate, code, AutocryptPreference.Mutual, T0));
        Assert.Equal(SetupCode, AutocryptSetupMessage.NormalizeSetupCode("1742 0185 6197 1303 7016 8412 3581 4441 0597"));
        Assert.Equal("free form code", AutocryptSetupMessage.NormalizeSetupCode("free form code"));
    }

    // ---- the setup message against gpg, as a black box (set ONECRYPTO_GPG to a gpg binary)

    // gpg's standard error from the last call, so a failing assertion says why
    private static string gpgError = "";

    private static (int Exit, byte[] Out) Gpg(string home, byte[] stdin, params string[] args)
    {
        string? gpg = Environment.GetEnvironmentVariable("ONECRYPTO_GPG");
        var psi = new ProcessStartInfo(gpg!) { RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true };
        foreach (string a in new[] { "--homedir", home, "--batch", "--no-tty", "--pinentry-mode", "loopback" }.Concat(args))
        {
            psi.ArgumentList.Add(a);
        }

        using Process p = Process.Start(psi)!;
        Task<string> err = p.StandardError.ReadToEndAsync();
        var ms = new MemoryStream();
        Task copy = p.StandardOutput.BaseStream.CopyToAsync(ms);
        p.StandardInput.BaseStream.Write(stdin);
        p.StandardInput.Close();
        p.WaitForExit();
        copy.Wait();
        gpgError = err.Result;
        return (p.ExitCode, ms.ToArray());
    }

    [Fact]
    public void SetupMessagesGoBothWaysWithGnuPG()
    {
        Assert.SkipWhen(Environment.GetEnvironmentVariable("ONECRYPTO_GPG") is null, "set ONECRYPTO_GPG to a gpg binary");
        string home = Path.Combine(Path.GetTempPath(), "acgpg-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(home);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(home, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        try
        {
            // gpg opens the specification's message with the specification's code, and ours with ours.
            (int exit, byte[] plain) = Gpg(home, SetupMessage, "--passphrase", SetupCode, "--decrypt");
            Assert.True(exit == 0, gpgError);
            Assert.StartsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----", Encoding.ASCII.GetString(plain), StringComparison.Ordinal);

            PgpCertificate secret = AutocryptSetupMessage.Open(SetupMessage, SetupCode, T0).Content!.Certificate;
            string code = AutocryptSetupMessage.GenerateSetupCode();
            string ours = AutocryptSetupMessage.Create(secret, code, AutocryptPreference.Mutual, T0);
            (exit, plain) = Gpg(home, Encoding.ASCII.GetBytes(ours), "--passphrase", code, "--decrypt");
            Assert.True(exit == 0, gpgError);
            Assert.Contains("Autocrypt-Prefer-Encrypt: mutual", Encoding.ASCII.GetString(plain), StringComparison.Ordinal);

            // gpg makes a setup message the way the specification describes it, and we open it.
            (exit, byte[] theirs) = Gpg(home, plain, "--passphrase", code, "--symmetric", "--armor", "--cipher-algo", "AES128", "--s2k-mode", "3", "--s2k-digest-algo", "SHA256");
            Assert.True(exit == 0, gpgError);
            AutocryptSetupResult r = AutocryptSetupMessage.Open(theirs, code, T0);
            Assert.True(r.IsSuccess, r.Reason);
            Assert.Equal(secret.Fingerprint, r.Content!.Certificate.Fingerprint);
        }
        finally
        {
            Directory.Delete(home, recursive: true);
        }
    }
}
