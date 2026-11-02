using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>The <c>prefer-encrypt</c> attribute of an Autocrypt header (Autocrypt Level 1, "The Autocrypt Header").</summary>
public enum AutocryptPreference
{
    /// <summary>No attribute, or a value other than <c>mutual</c>.</summary>
    NoPreference = 0,

    /// <summary><c>prefer-encrypt=mutual</c>: encrypt by default with peers who say the same.</summary>
    Mutual = 1,
}

/// <summary>Why an <c>Autocrypt</c> or <c>Autocrypt-Gossip</c> header value is not valid.</summary>
public enum AutocryptHeaderError
{
    /// <summary>The header is valid.</summary>
    None = 0,

    /// <summary>The value is empty or only white space.</summary>
    Empty,

    /// <summary>The header, with its name and folding, is over 10 KiB (Level 1: "MUAs SHOULD treat such headers as invalid").</summary>
    TooLarge,

    /// <summary>The text is not a list of <c>name=value</c> attributes separated by semicolons.</summary>
    Malformed,

    /// <summary>There is no <c>addr</c> attribute.</summary>
    MissingAddr,

    /// <summary>The <c>addr</c> value is not a single mail address.</summary>
    InvalidAddr,

    /// <summary>An attribute appears twice.</summary>
    DuplicateAttribute,

    /// <summary>An attribute without a leading underscore is not one this level knows ("critical"), so the whole header is invalid.</summary>
    UnsupportedCriticalAttribute,

    /// <summary>There is no <c>keydata</c> attribute.</summary>
    MissingKeyData,

    /// <summary>The key data is not Base64, or is not a binary OpenPGP transferable key.</summary>
    InvalidKeyData,

    /// <summary>The key data holds more than one key, or secret key material.</summary>
    KeyNotSinglePublicCertificate,

    /// <summary>The <c>addr</c> differs from the address the header must be valid for (the From address of the message).</summary>
    AddressMismatch,
}

/// <summary>A malformed Autocrypt header, from the throwing <see cref="AutocryptHeader.Parse"/>.</summary>
public sealed class AutocryptFormatException : FormatException
{
    /// <summary>Creates the exception.</summary>
    /// <param name="error">Why the header is invalid.</param>
    public AutocryptFormatException(AutocryptHeaderError error)
        : base("not a valid Autocrypt header: " + error)
    {
        Error = error;
    }

    /// <summary>Creates the exception.</summary>
    public AutocryptFormatException()
        : this(AutocryptHeaderError.Malformed)
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">A description.</param>
    public AutocryptFormatException(string message)
        : base(message)
    {
        Error = AutocryptHeaderError.Malformed;
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">A description.</param>
    /// <param name="inner">The cause.</param>
    public AutocryptFormatException(string message, Exception inner)
        : base(message, inner)
    {
        Error = AutocryptHeaderError.Malformed;
    }

    /// <summary>Why the header is invalid.</summary>
    public AutocryptHeaderError Error { get; }
}

/// <summary>
/// The value of an <c>Autocrypt</c> header, or of an <c>Autocrypt-Gossip</c> header, which has the same form (Autocrypt Level 1.1). It carries one mail address,
/// an optional encryption preference and one public key. The class works on header <em>values</em> and dates; finding the headers in a message is mail parsing
/// and belongs to the caller.
/// </summary>
public sealed class AutocryptHeader
{
    /// <summary>The longest header, counting its name, colon, space and folding, that is valid (10 KiB).</summary>
    public const int MaxHeaderLength = 10 * 1024;

    private const int NameAndSeparatorLength = 11; // "Autocrypt: "

    private readonly byte[] _keyData;

    private AutocryptHeader(string address, AutocryptPreference preference, byte[] keyData)
    {
        Address = address;
        PreferEncrypt = preference;
        _keyData = keyData;
    }

    /// <summary>The address the header is valid for, as written.</summary>
    public string Address { get; }

    /// <summary>The preference. Always <see cref="AutocryptPreference.NoPreference"/> for gossip, which must not state one.</summary>
    public AutocryptPreference PreferEncrypt { get; }

    /// <summary>The binary transferable public key (a copy).</summary>
    public byte[] KeyData => (byte[])_keyData.Clone();

    /// <summary>The key as a certificate. Binding is not checked; judge it at your own reference time.</summary>
    public PgpCertificate Certificate => PgpCertificate.Parse(_keyData);

    /// <summary>
    /// Reads a header value (the text after <c>Autocrypt:</c>, folding included). Attributes are separated by <c>;</c>, <c>keydata</c> runs to the end, an attribute
    /// whose name starts with <c>_</c> is ignored when unknown, any other unknown attribute makes the header invalid, and a <c>prefer-encrypt</c> other than
    /// <c>mutual</c> means no preference.
    /// </summary>
    /// <param name="value">The header value.</param>
    /// <param name="header">The header, or null.</param>
    /// <param name="error">Why it is invalid, or <see cref="AutocryptHeaderError.None"/>.</param>
    /// <returns>True when the header is valid.</returns>
    public static bool TryParse(string? value, out AutocryptHeader? header, out AutocryptHeaderError error)
    {
        header = null;
        error = AutocryptHeaderError.None;
        if (string.IsNullOrWhiteSpace(value))
        {
            error = AutocryptHeaderError.Empty;
            return false;
        }

        if (value.Length + NameAndSeparatorLength > MaxHeaderLength)
        {
            error = AutocryptHeaderError.TooLarge;
            return false;
        }

        // RFC 5322 §2.2.3: folding is CRLF before white space; drop the line breaks, keep the white space.
        string text = value.Replace("\r", string.Empty, StringComparison.Ordinal).Replace("\n", string.Empty, StringComparison.Ordinal);
        string? addr = null;
        string? keydata = null;
        var preference = AutocryptPreference.NoPreference;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        int pos = 0;
        while (pos < text.Length)
        {
            int eq = text.IndexOf('=', pos);
            if (eq < 0)
            {
                // Only a trailing separator or white space may be left without an attribute.
                if (text[pos..].Trim(' ', '\t', ';').Length == 0)
                {
                    break;
                }

                error = AutocryptHeaderError.Malformed;
                return false;
            }

            string name = text[pos..eq].Trim(' ', '\t', ';').ToLowerInvariant();
            if (name.Length == 0 || name.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')))
            {
                error = AutocryptHeaderError.Malformed;
                return false;
            }

            if (!seen.Add(name))
            {
                error = AutocryptHeaderError.DuplicateAttribute;
                return false;
            }

            if (name == "keydata")
            {
                // "keydata MUST be the last attribute": it takes everything that follows.
                keydata = text[(eq + 1)..].Trim(' ', '\t', ';');
                pos = text.Length;
                break;
            }

            int end = text.IndexOf(';', eq + 1);
            string attr = (end < 0 ? text[(eq + 1)..] : text[(eq + 1)..end]).Trim(' ', '\t');
            pos = end < 0 ? text.Length : end + 1;
            switch (name)
            {
                case "addr":
                    addr = attr;
                    break;
                case "prefer-encrypt":
                    preference = string.Equals(attr, "mutual", StringComparison.OrdinalIgnoreCase) ? AutocryptPreference.Mutual : AutocryptPreference.NoPreference;
                    break;
                default:
                    if (name[0] != '_')
                    {
                        error = AutocryptHeaderError.UnsupportedCriticalAttribute;
                        return false;
                    }

                    break;
            }
        }

        if (addr is null)
        {
            error = AutocryptHeaderError.MissingAddr;
            return false;
        }

        if (!IsAddress(addr))
        {
            error = AutocryptHeaderError.InvalidAddr;
            return false;
        }

        if (keydata is null || keydata.Length == 0)
        {
            error = AutocryptHeaderError.MissingKeyData;
            return false;
        }

        byte[] data;
        try
        {
            data = Convert.FromBase64String(new string([.. keydata.Where(c => c is not (' ' or '\t'))]));
        }
        catch (FormatException)
        {
            error = AutocryptHeaderError.InvalidKeyData;
            return false;
        }

        // The key data is binary (never armored), and exactly one public transferable key.
        if (data.Length == 0 || (data[0] & 0x80) == 0)
        {
            error = AutocryptHeaderError.InvalidKeyData;
            return false;
        }

        try
        {
            IReadOnlyList<TransferableKey> keys = TransferableKey.ParseAll(PacketParser.ParseAll(data));
            if (keys.Count != 1 || keys[0].IsSecret)
            {
                error = AutocryptHeaderError.KeyNotSinglePublicCertificate;
                return false;
            }
        }
        catch (FormatException)
        {
            error = AutocryptHeaderError.InvalidKeyData;
            return false;
        }

        header = new AutocryptHeader(addr, preference, data);
        return true;
    }

    /// <summary>Reads a header value.</summary>
    /// <param name="value">The header value.</param>
    /// <returns>The header.</returns>
    /// <exception cref="AutocryptFormatException">The value is not a valid header; <see cref="AutocryptFormatException.Error"/> says why.</exception>
    public static AutocryptHeader Parse(string value) =>
        TryParse(value, out AutocryptHeader? h, out AutocryptHeaderError e) ? h! : throw new AutocryptFormatException(e);

    /// <summary>Builds a header for an address and a public key.</summary>
    /// <param name="address">The address; the From address of the messages it will go on.</param>
    /// <param name="certificate">The public key to publish; a secret certificate is reduced to its public form.</param>
    /// <param name="preference">The preference to announce.</param>
    /// <returns>The header.</returns>
    /// <exception cref="ArgumentException">The address is not a single mail address.</exception>
    public static AutocryptHeader Create(string address, PgpCertificate certificate, AutocryptPreference preference = AutocryptPreference.NoPreference)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(certificate);
        if (!IsAddress(address))
        {
            throw new ArgumentException("not a single mail address", nameof(address));
        }

        byte[] data = certificate.ExportPublic();
        return new AutocryptHeader(address, preference, data);
    }

    /// <summary>Checks that the header may be used for a message from <paramref name="fromAddress"/>: the <c>addr</c> must equal it (ASCII case-insensitively).</summary>
    /// <param name="fromAddress">The single address of the message's From header.</param>
    /// <returns>True when they match.</returns>
    public bool IsValidFor(string fromAddress) => string.Equals(Address, fromAddress, StringComparison.OrdinalIgnoreCase);

    /// <summary>The header value: attributes in the order <c>addr</c>, <c>prefer-encrypt</c> (only when mutual), <c>keydata</c>, with the Base64 folded.</summary>
    public string ToHeaderValue()
    {
        var sb = new StringBuilder();
        sb.Append("addr=").Append(Address).Append("; ");
        if (PreferEncrypt == AutocryptPreference.Mutual)
        {
            sb.Append("prefer-encrypt=mutual; ");
        }

        sb.Append("keydata=");
        string b64 = Convert.ToBase64String(_keyData);
        for (int i = 0; i < b64.Length; i += 76)
        {
            sb.Append("\r\n ").Append(b64, i, Math.Min(76, b64.Length - i));
        }

        return sb.ToString();
    }

    /// <summary>The whole header field, name included and folded with CR LF (no final line break).</summary>
    /// <param name="name"><c>Autocrypt</c> (default) or <c>Autocrypt-Gossip</c>.</param>
    public string ToHeaderField(string name = "Autocrypt") => name + ": " + ToHeaderValue();

    /// <summary>The same key and address as a gossip header: no preference, because gossip must not carry one.</summary>
    public AutocryptHeader AsGossip() => new(Address, AutocryptPreference.NoPreference, _keyData);

    private static bool IsAddress(string a)
    {
        int at = a.IndexOf('@', StringComparison.Ordinal);
        return a.Length is > 0 and <= 320 && at > 0 && at == a.LastIndexOf('@') && at < a.Length - 1 && !a.Any(c => char.IsControl(c) || char.IsWhiteSpace(c) || c is '<' or '>' or ',' or ';');
    }
}

/// <summary>What Autocrypt remembers about one communication peer (Level 1 "Communication Peers"). Immutable: updates return a new value.</summary>
public sealed record AutocryptPeer
{
    /// <summary>The peer's address in lower case.</summary>
    public required string Address { get; init; }

    /// <summary>The effective date of the newest message seen from the peer, with or without a header (<c>last_seen</c>).</summary>
    public DateTimeOffset? LastSeen { get; init; }

    /// <summary>The effective date of the newest message with a valid Autocrypt header (<c>autocrypt_timestamp</c>).</summary>
    public DateTimeOffset? AutocryptTimestamp { get; init; }

    /// <summary>The key from that header (<c>public_key</c>), binary; null if none yet. Do not modify the array.</summary>
    public byte[]? PublicKey { get; init; }

    /// <summary>The preference from that header (<c>prefer_encrypt</c>).</summary>
    public AutocryptPreference PreferEncrypt { get; init; }

    /// <summary>The effective date of the newest message that gossiped a key for the peer (<c>gossip_timestamp</c>).</summary>
    public DateTimeOffset? GossipTimestamp { get; init; }

    /// <summary>The gossiped key (<c>gossip_key</c>), binary; null if none. Do not modify the array.</summary>
    public byte[]? GossipKey { get; init; }

    /// <summary>The key used for comparing addresses: lower case, no surrounding white space.</summary>
    /// <param name="address">A mail address.</param>
    public static string NormalizeAddress(string address)
    {
        ArgumentNullException.ThrowIfNull(address);
        return address.Trim().ToLowerInvariant();
    }

    /// <summary>
    /// Updates a peer from a received message (Level 1 "Updating Autocrypt Peer State"). The message is ignored when it is a report, has more than one From address
    /// or is spam; an <c>Autocrypt</c> header counts only when it is valid for the From address and is the only valid one.
    /// </summary>
    /// <param name="previous">What is known about the sender, or null.</param>
    /// <param name="message">The facts about the message.</param>
    /// <returns>The new state and what happened.</returns>
    public static AutocryptUpdate Apply(AutocryptPeer? previous, AutocryptMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);
        string address = NormalizeAddress(message.FromAddress);
        AutocryptPeer current = previous ?? new AutocryptPeer { Address = address };
        if (message.IsAutoGeneratedReport || message.FromAddressCount != 1 || message.IsSpam)
        {
            return new AutocryptUpdate(current, false, "the message is not used for Autocrypt (report, several From addresses or spam)", []);
        }

        var valid = new List<AutocryptHeader>();
        var errors = new List<AutocryptHeaderError>();
        foreach (string raw in message.AutocryptHeaders)
        {
            if (AutocryptHeader.TryParse(raw, out AutocryptHeader? h, out AutocryptHeaderError e) && h!.IsValidFor(message.FromAddress))
            {
                valid.Add(h);
            }
            else
            {
                errors.Add(e == AutocryptHeaderError.None ? AutocryptHeaderError.AddressMismatch : e);
            }
        }

        DateTimeOffset date = message.EffectiveDate;

        // "If the message's effective date is older than autocrypt_timestamp, no changes are required."
        if (current.AutocryptTimestamp is { } at && date < at)
        {
            return new AutocryptUpdate(current, false, "the message is older than the newest header seen", errors);
        }

        AutocryptPeer next = current.LastSeen is not { } seen || date > seen ? current with { LastSeen = date } : current;

        // "If there is more than one valid header, this SHOULD be treated as an error, and all Autocrypt headers discarded as invalid."
        if (valid.Count != 1)
        {
            string why = valid.Count == 0 ? "no valid Autocrypt header" : "more than one valid Autocrypt header, so none is used";
            return new AutocryptUpdate(next, !ReferenceEquals(next, current), why, errors);
        }

        next = next with { AutocryptTimestamp = date, PublicKey = valid[0].KeyData, PreferEncrypt = valid[0].PreferEncrypt };
        return new AutocryptUpdate(next, true, string.Empty, errors);
    }

    /// <summary>
    /// Updates a peer from a gossip header found in the encrypted payload of a received message (Level 1 "Updating Autocrypt Peer State from Key Gossip").
    /// </summary>
    /// <param name="previous">What is known about the gossiped address, or null.</param>
    /// <param name="gossip">The gossip header's value.</param>
    /// <param name="message">The facts about the carrying message; only its dates and its To, Cc and Reply-To addresses are used.</param>
    /// <returns>The new state; unchanged (with the reason) when the header is invalid, names an address the message did not address, or is older than what is held.</returns>
    public static AutocryptUpdate ApplyGossip(AutocryptPeer? previous, string gossip, AutocryptGossipContext message)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (!AutocryptHeader.TryParse(gossip, out AutocryptHeader? h, out AutocryptHeaderError e))
        {
            return new AutocryptUpdate(previous ?? new AutocryptPeer { Address = string.Empty }, false, "the gossip header is invalid", [e]);
        }

        string address = NormalizeAddress(h!.Address);
        AutocryptPeer current = previous ?? new AutocryptPeer { Address = address };
        if (!message.RecipientAddresses.Any(a => NormalizeAddress(a) == address))
        {
            return new AutocryptUpdate(current, false, "the gossiped address is not in To, Cc or Reply-To", []);
        }

        DateTimeOffset date = message.EffectiveDate;
        if (current.GossipTimestamp is { } t && t > date)
        {
            return new AutocryptUpdate(current, false, "the held gossip is newer than the message", []);
        }

        return new AutocryptUpdate(current with { GossipTimestamp = date, GossipKey = h.KeyData }, true, string.Empty, []);
    }
}

/// <summary>The facts about a received message that Autocrypt needs; the caller reads them from the mail.</summary>
public sealed class AutocryptMessage
{
    /// <summary>The single address of the From header.</summary>
    public required string FromAddress { get; init; }

    /// <summary>The <c>Date</c> header, or null if there is none or it could not be read.</summary>
    public DateTimeOffset? Date { get; init; }

    /// <summary>When the message was received. Required: there is no default clock.</summary>
    public required DateTimeOffset Received { get; init; }

    /// <summary>The values of every <c>Autocrypt</c> header of the message (all of them, not just the first).</summary>
    public IReadOnlyList<string> AutocryptHeaders { get; init; } = [];

    /// <summary>How many addresses the From header has (default 1).</summary>
    public int FromAddressCount { get; init; } = 1;

    /// <summary>True for a <c>multipart/report</c> message (default false).</summary>
    public bool IsAutoGeneratedReport { get; init; }

    /// <summary>True when the mail client believes the message is spam (default false).</summary>
    public bool IsSpam { get; init; }

    /// <summary>The effective date: the <c>Date</c> if present and not after the time received, otherwise the time received.</summary>
    public DateTimeOffset EffectiveDate => Date is { } d && d <= Received ? d : Received;
}

/// <summary>The facts about a message carrying gossip.</summary>
public sealed class AutocryptGossipContext
{
    /// <summary>The addresses of the To, Cc and Reply-To headers.</summary>
    public required IReadOnlyList<string> RecipientAddresses { get; init; }

    /// <summary>The <c>Date</c> header, or null.</summary>
    public DateTimeOffset? Date { get; init; }

    /// <summary>When the message was received.</summary>
    public required DateTimeOffset Received { get; init; }

    /// <summary>The effective date: the <c>Date</c> if present and not after the time received, otherwise the time received.</summary>
    public DateTimeOffset EffectiveDate => Date is { } d && d <= Received ? d : Received;
}

/// <summary>The outcome of updating a peer.</summary>
public sealed class AutocryptUpdate
{
    internal AutocryptUpdate(AutocryptPeer peer, bool changed, string note, IReadOnlyList<AutocryptHeaderError> headerErrors)
    {
        Peer = peer;
        Changed = changed;
        Note = note;
        HeaderErrors = headerErrors;
    }

    /// <summary>The peer after the update (the same value when nothing changed).</summary>
    public AutocryptPeer Peer { get; }

    /// <summary>True when the state differs from before the update.</summary>
    public bool Changed { get; }

    /// <summary>Why the message did not (fully) update the peer; empty when it did.</summary>
    public string Note { get; }

    /// <summary>Why each rejected header was rejected.</summary>
    public IReadOnlyList<AutocryptHeaderError> HeaderErrors { get; }
}

/// <summary>The Level 1 recommendation for encrypting a message (<c>ui-recommendation</c>).</summary>
public enum AutocryptRecommendation
{
    /// <summary>Encryption is not possible.</summary>
    Disable = 0,

    /// <summary>Encryption is possible but the recipient may not be able to read it; do not default to it.</summary>
    Discourage = 1,

    /// <summary>Encryption is possible; offer it but do not default to it.</summary>
    Available = 2,

    /// <summary>Encrypt by default.</summary>
    Encrypt = 3,
}

/// <summary>Facts about the message being composed.</summary>
public sealed class AutocryptComposeContext
{
    /// <summary>The time the recommendation is for; keys expired or revoked then are treated as absent. Required.</summary>
    public required DateTimeOffset Now { get; init; }

    /// <summary>The sender's own <c>prefer_encrypt</c> setting (default no preference).</summary>
    public AutocryptPreference OwnPreference { get; init; }

    /// <summary>True when the message replies to an encrypted message (default false).</summary>
    public bool IsReplyToEncrypted { get; init; }

    /// <summary>Overrides the check that a key can encrypt at <see cref="Now"/>; null uses <see cref="AutocryptRecommender.CanEncrypt"/>.</summary>
    public Func<byte[], DateTimeOffset, bool>? IsKeyUsable { get; init; }
}

/// <summary>The recommendation for one recipient.</summary>
/// <param name="Address">The recipient's address as given.</param>
/// <param name="Recommendation">The recommendation.</param>
/// <param name="TargetKey">The key to encrypt to, or null when the recommendation is <see cref="AutocryptRecommendation.Disable"/>.</param>
/// <param name="Reason">A sentence saying how the recommendation came about.</param>
public sealed record AutocryptRecipientRecommendation(string Address, AutocryptRecommendation Recommendation, byte[]? TargetKey, string Reason);

/// <summary>The recommendation for a whole message.</summary>
/// <param name="Recommendation">The aggregate recommendation.</param>
/// <param name="Recipients">The recommendation for each recipient, in order.</param>
public sealed record AutocryptMessageRecommendation(AutocryptRecommendation Recommendation, IReadOnlyList<AutocryptRecipientRecommendation> Recipients)
{
    /// <summary>The keys to encrypt to, by lower-case address (the merge of all recipients' target keys).</summary>
    public IReadOnlyDictionary<string, byte[]> TargetKeys => Recipients.Where(r => r.TargetKey is not null).ToDictionary(r => AutocryptPeer.NormalizeAddress(r.Address), r => r.TargetKey!);
}

/// <summary>The Level 1 recommendation algorithm (Level 1 "Provide a recommendation for message encryption"). It is a pure function of the peer states, the context and the time.</summary>
public static class AutocryptRecommender
{
    // Level 1: "If autocrypt_timestamp is more than 35 days older than last_seen, set preliminary-recommendation to discourage."
    private static readonly TimeSpan StaleAfter = TimeSpan.FromDays(35);

    /// <summary>Recommends for a message to several recipients.</summary>
    /// <param name="recipients">The addresses of To, Cc and Bcc.</param>
    /// <param name="peers">What is known about peers, by address (any case). Missing entries mean unknown peers.</param>
    /// <param name="context">The message and the time.</param>
    /// <returns>The aggregate and per-recipient recommendations. With no recipients the answer is <see cref="AutocryptRecommendation.Disable"/>.</returns>
    public static AutocryptMessageRecommendation Recommend(IReadOnlyList<string> recipients, IReadOnlyDictionary<string, AutocryptPeer> peers, AutocryptComposeContext context)
    {
        ArgumentNullException.ThrowIfNull(recipients);
        ArgumentNullException.ThrowIfNull(peers);
        ArgumentNullException.ThrowIfNull(context);
        var each = new List<AutocryptRecipientRecommendation>();
        foreach (string address in recipients)
        {
            string key = AutocryptPeer.NormalizeAddress(address);
            AutocryptPeer? peer = peers.TryGetValue(key, out AutocryptPeer? p) ? p : peers.Values.FirstOrDefault(v => v.Address == key);
            each.Add(ForPeer(address, peer, context));
        }

        // "The earliest matching rule takes precedence": any disable; all encrypt; any discourage; otherwise available.
        AutocryptRecommendation total = each.Count == 0 || each.Any(r => r.Recommendation == AutocryptRecommendation.Disable) ? AutocryptRecommendation.Disable
            : each.All(r => r.Recommendation == AutocryptRecommendation.Encrypt) ? AutocryptRecommendation.Encrypt
            : each.Any(r => r.Recommendation == AutocryptRecommendation.Discourage) ? AutocryptRecommendation.Discourage
            : AutocryptRecommendation.Available;
        return new AutocryptMessageRecommendation(total, each);
    }

    /// <summary>Recommends for one recipient.</summary>
    /// <param name="address">The recipient's address.</param>
    /// <param name="peer">What is known about the recipient, or null.</param>
    /// <param name="context">The message and the time.</param>
    public static AutocryptRecipientRecommendation ForPeer(string address, AutocryptPeer? peer, AutocryptComposeContext context)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(context);
        if (peer is null)
        {
            return new AutocryptRecipientRecommendation(address, AutocryptRecommendation.Disable, null, "nothing is known about the recipient");
        }

        Func<byte[], DateTimeOffset, bool> usable = context.IsKeyUsable ?? CanEncrypt;

        // "If either public_key or gossip_key is revoked, expired, or otherwise known to be unusable for encryption, then treat that key as though it were null."
        byte[]? publicKey = peer.PublicKey is { } pk && usable(pk, context.Now) ? pk : null;
        byte[]? gossipKey = peer.GossipKey is { } gk && usable(gk, context.Now) ? gk : null;
        if (publicKey is null && gossipKey is null)
        {
            return new AutocryptRecipientRecommendation(address, AutocryptRecommendation.Disable, null, "the recipient has no key that can encrypt");
        }

        AutocryptRecommendation preliminary;
        byte[] target;
        string how;
        if (publicKey is null)
        {
            target = gossipKey!;
            preliminary = AutocryptRecommendation.Discourage;
            how = "only a gossiped key is known";
        }
        else
        {
            target = publicKey;
            bool old = peer.AutocryptTimestamp is { } ts && peer.LastSeen is { } seen && seen - ts > StaleAfter;
            preliminary = old ? AutocryptRecommendation.Discourage : AutocryptRecommendation.Available;
            how = old ? "the newest Autocrypt header is more than 35 days older than the newest message" : "the recipient's key is current";
        }

        // "Deciding to Encrypt by Default"
        bool reply = preliminary is AutocryptRecommendation.Available or AutocryptRecommendation.Discourage && context.IsReplyToEncrypted;
        bool mutual = preliminary == AutocryptRecommendation.Available && peer.PreferEncrypt == AutocryptPreference.Mutual && context.OwnPreference == AutocryptPreference.Mutual;
        if (reply || mutual)
        {
            return new AutocryptRecipientRecommendation(address, AutocryptRecommendation.Encrypt, target, reply ? "reply to an encrypted message" : "both sides prefer encryption");
        }

        return new AutocryptRecipientRecommendation(address, preliminary, target, how);
    }

    /// <summary>True when the binary key parses and has a key that is valid at <paramref name="at"/> and may encrypt communications.</summary>
    /// <param name="keyData">A binary transferable public key.</param>
    /// <param name="at">The time.</param>
    public static bool CanEncrypt(byte[] keyData, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(keyData);
        try
        {
            PgpCertificate cert = PgpCertificate.Parse(keyData);
            foreach (PgpKey k in cert.Keys)
            {
                PgpKeyState st = k.StateAt(at);
                if (st.IsValid && (st.Usage & (PgpKeyUsage.EncryptCommunications | PgpKeyUsage.EncryptStorage)) != 0)
                {
                    return true;
                }
            }

            return false;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

/// <summary>What <see cref="AutocryptSetupMessage.Open"/> found.</summary>
public enum AutocryptSetupOutcome
{
    /// <summary>The message opened and held a secret key.</summary>
    Opened = 0,

    /// <summary>The setup code is wrong, or the message was altered: the two cannot be told apart.</summary>
    WrongCodeOrCorrupt = 1,

    /// <summary>The text has no armored OpenPGP message, or the message is not a password-encrypted one.</summary>
    NotASetupMessage = 2,

    /// <summary>The message opened but does not hold a secret key.</summary>
    NoSecretKey = 3,

    /// <summary>The content is larger than the limit.</summary>
    TooLarge = 4,
}

/// <summary>An Autocrypt Setup Message that was opened.</summary>
public sealed class AutocryptSetupContent
{
    internal AutocryptSetupContent(PgpCertificate certificate, AutocryptPreference preference)
    {
        Certificate = certificate;
        PreferEncrypt = preference;
    }

    /// <summary>The account's transferable secret key.</summary>
    public PgpCertificate Certificate { get; }

    /// <summary>The <c>Autocrypt-Prefer-Encrypt</c> header of the key's armor.</summary>
    public AutocryptPreference PreferEncrypt { get; }
}

/// <summary>The result of opening a setup message.</summary>
public sealed class AutocryptSetupResult
{
    internal AutocryptSetupResult(AutocryptSetupOutcome outcome, string reason, AutocryptSetupContent? content)
    {
        Outcome = outcome;
        Reason = reason;
        Content = content;
    }

    /// <summary>How it ended.</summary>
    public AutocryptSetupOutcome Outcome { get; }

    /// <summary>True when the message opened.</summary>
    public bool IsSuccess => Outcome == AutocryptSetupOutcome.Opened;

    /// <summary>A sentence saying why, empty on success.</summary>
    public string Reason { get; }

    /// <summary>The key and preference when <see cref="IsSuccess"/>.</summary>
    public AutocryptSetupContent? Content { get; }
}

/// <summary>
/// The Autocrypt Setup Message payload (Level 1 §"Autocrypt Setup Message"): the account's armored secret key, encrypted with the setup code as an OpenPGP
/// password. This class makes and opens the armored <c>-----BEGIN PGP MESSAGE-----</c> block that is the body of the <c>application/autocrypt-setup</c> part;
/// building the e-mail around it (<c>Autocrypt-Setup-Message: v1</c>, the MIME structure) is the mail client's.
/// </summary>
public static class AutocryptSetupMessage
{
    private const int MaxMessageBytes = 4 << 20;
    private const int MaxContentBytes = 2 << 20;

    /// <summary>Makes a setup code: 36 random decimal digits in nine blocks of four separated by dashes, about 119 bits.</summary>
    /// <returns>For example <c>9503-1923-2307-1980-7833-0983-1998-7562-1111</c>.</returns>
    public static string GenerateSetupCode()
    {
        var sb = new StringBuilder(44);
        for (int i = 0; i < 36; i++)
        {
            if (i > 0 && i % 4 == 0)
            {
                sb.Append('-');
            }

            sb.Append((char)('0' + RandomNumberGenerator.GetInt32(10)));
        }

        return sb.ToString();
    }

    /// <summary>
    /// Brings a typed setup code to its canonical form. A code made only of digits, spaces and dashes with 36 digits becomes nine dash-separated blocks of four;
    /// anything else is returned unchanged, because other implementations may use a free-form passphrase.
    /// </summary>
    /// <param name="code">The code as typed.</param>
    public static string NormalizeSetupCode(string code)
    {
        ArgumentNullException.ThrowIfNull(code);
        if (code.All(c => char.IsAsciiDigit(c) || c is ' ' or '-'))
        {
            string digits = new([.. code.Where(char.IsAsciiDigit)]);
            if (digits.Length == 36)
            {
                return string.Join('-', Enumerable.Range(0, 9).Select(i => digits.Substring(i * 4, 4)));
            }
        }

        return code;
    }

    /// <summary>Makes the armored encrypted block for an account.</summary>
    /// <param name="secretKey">The account's transferable secret key. It is exported as it is; a key protected by its own passphrase stays protected inside.</param>
    /// <param name="setupCode">The code to encrypt with; see <see cref="GenerateSetupCode"/>. It must never travel in the mail.</param>
    /// <param name="preference">Written as the <c>Autocrypt-Prefer-Encrypt</c> header of the key's armor.</param>
    /// <param name="now">The time the message is made at; required, there is no default clock.</param>
    /// <returns>The armored message, with <c>Passphrase-Format: numeric9x4</c> and <c>Passphrase-Begin</c> headers when the code has the standard form.</returns>
    /// <exception cref="ArgumentException">The certificate holds no secret key material, or the code is empty.</exception>
    public static string Create(PgpCertificate secretKey, string setupCode, AutocryptPreference preference, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(secretKey);
        ArgumentException.ThrowIfNullOrEmpty(setupCode);
        if (!secretKey.HasSecretKeyMaterial)
        {
            throw new ArgumentException("a setup message holds the secret key", nameof(secretKey));
        }

        using var keyBytes = new MemoryStream();
        secretKey.Transferable.WriteTo(keyBytes);
        var headers = new List<KeyValuePair<string, string>>();
        if (preference == AutocryptPreference.Mutual)
        {
            headers.Add(new("Autocrypt-Prefer-Encrypt", "mutual"));
        }

        string inner = Armor.Encode(ArmorKind.PrivateKey, keyBytes.ToArray(), new ArmorWriteOptions { Headers = headers });
        byte[] code = Encoding.UTF8.GetBytes(setupCode);
        try
        {
            using var plain = new MemoryStream(Encoding.ASCII.GetBytes(inner));
            using var encrypted = new MemoryStream();
            // Level 1: a symmetric-key encrypted session key packet followed by an integrity-protected data packet, the code through the iterated and salted S2K.
            PgpMessageWriter.Write(plain, encrypted, new PgpWriteOptions { Now = now, Passwords = [code], ForceSeipd1 = true });
            var outer = new List<KeyValuePair<string, string>>();
            if (NormalizeSetupCode(setupCode) == setupCode && setupCode.Length == 44 && setupCode.Count(c => c == '-') == 8)
            {
                outer.Add(new("Passphrase-Format", "numeric9x4"));
                outer.Add(new("Passphrase-Begin", setupCode[..2]));
            }

            return Armor.Encode(ArmorKind.Message, encrypted.ToArray(), new ArmorWriteOptions { Headers = outer });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(code);
        }
    }

    /// <summary>Reads the hints the armor headers give for a prompt: whether to show the nine-by-four form and the first digits of the code.</summary>
    /// <param name="armoredMessage">The body of the <c>application/autocrypt-setup</c> part; text around the armored block is ignored.</param>
    /// <returns>The format name (for example <c>numeric9x4</c>) and the begin digits, either null if absent; both null if no message block is found.</returns>
    public static (string? Format, string? Begin) ReadHints(ReadOnlyMemory<byte> armoredMessage)
    {
        if (armoredMessage.Length <= MaxMessageBytes && Armor.TryDecode(armoredMessage.Span, out ArmorBlock? block, out _) && block!.Kind == ArmorKind.Message)
        {
            return (Header(block, "Passphrase-Format"), Header(block, "Passphrase-Begin"));
        }

        return (null, null);
    }

    /// <summary>Opens a setup message with its code. The code is the only way in: no other key or password is tried, and a message that does not authenticate yields nothing.</summary>
    /// <param name="armoredMessage">The body of the <c>application/autocrypt-setup</c> part; text around the armored block (an HTML wrapper, for instance) is ignored.</param>
    /// <param name="setupCode">The code as typed; see <see cref="NormalizeSetupCode"/>, which is applied.</param>
    /// <param name="now">The reference time; required.</param>
    /// <returns>The outcome and, on success, the secret key and preference.</returns>
    public static AutocryptSetupResult Open(ReadOnlyMemory<byte> armoredMessage, string setupCode, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(setupCode);
        if (armoredMessage.Length > MaxMessageBytes)
        {
            return new AutocryptSetupResult(AutocryptSetupOutcome.TooLarge, "the message is larger than 4 MiB", null);
        }

        if (!Armor.TryDecode(armoredMessage.Span, out ArmorBlock? block, out OpenPgpFailure failure) || block!.Kind != ArmorKind.Message)
        {
            return new AutocryptSetupResult(AutocryptSetupOutcome.NotASetupMessage, "no armored OpenPGP message" + (block is null ? ": " + failure.Message : string.Empty), null);
        }

        byte[] code = Encoding.UTF8.GetBytes(NormalizeSetupCode(setupCode));
        try
        {
            using var sink = new CappedStream(MaxContentBytes);
            try
            {
                PgpMessageReader.Read(new MemoryStream(block.Data, false), sink, new PgpReadOptions { Now = now, MessagePasswords = [code], Require = PgpRequirement.Encrypted });
            }
            catch (PgpException e) when (e.Failure is PgpFailure.CannotDecrypt or PgpFailure.NoDecryptionKey)
            {
                return new AutocryptSetupResult(AutocryptSetupOutcome.WrongCodeOrCorrupt, "the setup code is wrong or the message was altered", null);
            }
            catch (PgpException e) when (e.Failure == PgpFailure.LimitExceeded)
            {
                return new AutocryptSetupResult(AutocryptSetupOutcome.TooLarge, "the content is larger than the limit", null);
            }
            catch (PgpException e)
            {
                return new AutocryptSetupResult(AutocryptSetupOutcome.NotASetupMessage, e.Message, null);
            }
            catch (FormatException e)
            {
                return new AutocryptSetupResult(AutocryptSetupOutcome.NotASetupMessage, e.Message, null);
            }
            catch (CappedStream.LimitException)
            {
                return new AutocryptSetupResult(AutocryptSetupOutcome.TooLarge, "the content is larger than the limit", null);
            }

            // The payload is an armored secret key; "all trailing data after the first ASCII-armor ending delimiter MUST be stripped".
            byte[] plain = sink.ToArray();
            ArmorBlock key;
            if (plain.Length > 0 && (plain[0] & 0x80) != 0)
            {
                key = new ArmorBlock("PGP PRIVATE KEY BLOCK", [], plain, false);
            }
            else if (!Armor.TryDecode(plain, out ArmorBlock? decoded, out _) || decoded!.Kind != ArmorKind.PrivateKey)
            {
                return new AutocryptSetupResult(AutocryptSetupOutcome.NoSecretKey, "the content is not an armored private key", null);
            }
            else
            {
                key = decoded;
            }

            try
            {
                PgpCertificate cert = PgpCertificate.Parse(key.Data);
                if (!cert.HasSecretKeyMaterial)
                {
                    return new AutocryptSetupResult(AutocryptSetupOutcome.NoSecretKey, "the key in the message has no secret key material", null);
                }

                AutocryptPreference pref = string.Equals(Header(key, "Autocrypt-Prefer-Encrypt"), "mutual", StringComparison.OrdinalIgnoreCase) ? AutocryptPreference.Mutual : AutocryptPreference.NoPreference;
                return new AutocryptSetupResult(AutocryptSetupOutcome.Opened, string.Empty, new AutocryptSetupContent(cert, pref));
            }
            catch (FormatException e)
            {
                return new AutocryptSetupResult(AutocryptSetupOutcome.NoSecretKey, "the key in the message is malformed: " + e.Message, null);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(code);
        }
    }

    private static string? Header(ArmorBlock b, string name) => b.Headers.FirstOrDefault(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase)).Value;

    private sealed class CappedStream : MemoryStream
    {
        private readonly int _limit;

        internal CappedStream(int limit)
        {
            _limit = limit;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            Check(count);
            base.Write(buffer, offset, count);
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Check(buffer.Length);
            base.Write(buffer);
        }

        public override void WriteByte(byte value)
        {
            Check(1);
            base.WriteByte(value);
        }

        private void Check(int more)
        {
            if (Length + more > _limit)
            {
                throw new LimitException();
            }
        }

        internal sealed class LimitException : IOException
        {
        }
    }
}
