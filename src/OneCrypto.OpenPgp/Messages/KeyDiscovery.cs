using System.Globalization;
using System.Text;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>Choices for <see cref="KeyDiscovery"/>.</summary>
public sealed class DiscoveryOptions
{
    /// <summary>The most certificates read from one response (default 32); later ones are dropped and reported.</summary>
    public int MaxCertificates { get; init; } = 32;

    /// <summary>
    /// Keep certifications and certification revocations made by other keys (default false for address lookups, which is what the Web Key Directory draft §5 and
    /// the keyserver specifications ask for; a response can otherwise carry thousands of them). Key revocations by any issuer are always kept, since a designated
    /// revoker's revocation is genuine, and so are the primary key's own signatures.
    /// </summary>
    public bool KeepThirdPartyCertifications { get; init; }
}

/// <summary>What was dropped from a discovery response and why.</summary>
/// <param name="Reason">A sentence for logs and reports.</param>
/// <param name="Fingerprint">The fingerprint of the certificate concerned, or null when it could not be read.</param>
public sealed record DiscoveryDrop(string Reason, byte[]? Fingerprint);

/// <summary>The certificates found in a response to a lookup, after filtering. Nothing here has been validated: binding signatures, expiry and revocation are judged by the caller at its own reference time.</summary>
public sealed class DiscoveredKeys
{
    internal DiscoveredKeys(IReadOnlyList<PgpCertificate> certificates, IReadOnlyList<DiscoveryDrop> dropped, int thirdPartySignaturesRemoved)
    {
        Certificates = certificates;
        Dropped = dropped;
        ThirdPartySignaturesRemoved = thirdPartySignaturesRemoved;
    }

    /// <summary>The certificates that answer the query, public only, in response order.</summary>
    public IReadOnlyList<PgpCertificate> Certificates { get; }

    /// <summary>Everything that was found but not kept: certificates without a matching User ID or key, secret keys, unreadable or surplus blocks.</summary>
    public IReadOnlyList<DiscoveryDrop> Dropped { get; }

    /// <summary>How many signatures by other keys were removed.</summary>
    public int ThirdPartySignaturesRemoved { get; }
}

/// <summary>
/// Turns the bytes a Web Key Directory or keyserver returned into the certificates that answer the query, and nothing else. A server is not trusted to return what
/// was asked for: a Web Key Directory response is cut down to the User ID with the queried address (draft-koch-openpgp-webkey-service §5), a fingerprint lookup
/// keeps only certificates that hold that key, secret key material is never accepted, and blocks that do not parse are skipped (draft-gallagher-openpgp-hkp §7.3).
/// The network clients live in <c>RecursiveAI.OneCrypto.Online</c>; this layer does no I/O.
/// </summary>
public static class KeyDiscovery
{
    private const string PublicBegin = "-----BEGIN PGP PUBLIC KEY BLOCK-----";

    /// <summary>
    /// Keeps the certificates that have a User ID for <paramref name="address"/>, each reduced to that User ID with its own signatures. Other User IDs and User
    /// Attributes are removed, as are third-party certifications unless <see cref="DiscoveryOptions.KeepThirdPartyCertifications"/> is set.
    /// </summary>
    /// <param name="response">The response body: binary packets, one or more armored public key blocks, or armor inside other text.</param>
    /// <param name="address">The queried mail address. The comparison ignores case and compares IDNA domains.</param>
    /// <param name="options">Choices; null for the defaults.</param>
    /// <returns>The certificates and a record of what was dropped. Never throws for bad input.</returns>
    public static DiscoveredKeys ForAddress(ReadOnlyMemory<byte> response, string address, DiscoveryOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(address);
        options ??= new DiscoveryOptions();
        var dropped = new List<DiscoveryDrop>();
        (string, string)? want = NormalizeAddress(address);
        if (want is null)
        {
            dropped.Add(new DiscoveryDrop("the queried address is not a mail address", null));
            return new DiscoveredKeys([], dropped, 0);
        }

        var kept = new List<PgpCertificate>();
        int removed = 0;
        foreach (TransferableKey key in Read(response, options, dropped))
        {
            var users = key.Users.Where(u => u.Identity is UserIdPacket id && Matches(id, want.Value)).ToList();
            if (users.Count == 0)
            {
                dropped.Add(new DiscoveryDrop("the certificate has no User ID with the queried address", FingerprintOf(key)));
                continue;
            }

            kept.Add(PgpCertificate.FromTransferable(Rebuild(key, users, !options.KeepThirdPartyCertifications, ref removed)));
        }

        return new DiscoveredKeys(kept, dropped, removed);
    }

    /// <summary>Keeps the certificates that contain the key with this fingerprint or key ID (as primary key or subkey).</summary>
    /// <param name="response">The response body.</param>
    /// <param name="fingerprintOrKeyId">A fingerprint (16, 20 or 32 octets; a version-prefixed issuer-fingerprint form is not accepted) or an eight-octet key ID.</param>
    /// <param name="options">Choices; null keeps third-party certifications. Every User ID of a matching certificate is kept; use <see cref="ForAddress"/> to cut a certificate down to one address.</param>
    /// <returns>The certificates and a record of what was dropped. Never throws for bad input.</returns>
    public static DiscoveredKeys ForKey(ReadOnlyMemory<byte> response, ReadOnlySpan<byte> fingerprintOrKeyId, DiscoveryOptions? options = null)
    {
        options ??= new DiscoveryOptions { KeepThirdPartyCertifications = true };
        byte[] want = fingerprintOrKeyId.ToArray();
        var dropped = new List<DiscoveryDrop>();
        var kept = new List<PgpCertificate>();
        int removed = 0;
        foreach (TransferableKey key in Read(response, options, dropped))
        {
            var cert = PgpCertificate.FromTransferable(key);
            if (want.Length is 8 or 16 or 20 or 32 && cert.FindKey(want) is not null)
            {
                kept.Add(options.KeepThirdPartyCertifications ? cert : PgpCertificate.FromTransferable(Rebuild(key, key.Users, true, ref removed)));
            }
            else
            {
                dropped.Add(new DiscoveryDrop("the certificate does not contain the requested key", FingerprintOf(key)));
            }
        }

        return new DiscoveredKeys(kept, dropped, removed);
    }

    /// <summary>Reads every public certificate in a response without judging which query it answers (for an index lookup the caller already chose from).</summary>
    /// <param name="response">The response body.</param>
    /// <param name="options">Choices; null for the defaults.</param>
    /// <returns>The certificates and a record of what was dropped. Never throws for bad input.</returns>
    public static DiscoveredKeys ReadAll(ReadOnlyMemory<byte> response, DiscoveryOptions? options = null)
    {
        options ??= new DiscoveryOptions { KeepThirdPartyCertifications = true };
        var dropped = new List<DiscoveryDrop>();
        List<PgpCertificate> kept = [.. Read(response, options, dropped).Select(PgpCertificate.FromTransferable)];
        return new DiscoveredKeys(kept, dropped, 0);
    }

    // Binary packets, or any number of armored blocks anywhere in the text. A block that does not decode is skipped.
    private static List<TransferableKey> Read(ReadOnlyMemory<byte> response, DiscoveryOptions options, List<DiscoveryDrop> dropped)
    {
        var found = new List<TransferableKey>();
        var chunks = new List<byte[]>();
        ReadOnlySpan<byte> span = response.Span;
        if (!span.IsEmpty && (span[0] & 0x80) != 0)
        {
            chunks.Add(span.ToArray());
        }
        else
        {
            byte[] begin = Encoding.ASCII.GetBytes(PublicBegin);
            int pos = 0;
            while (pos < span.Length)
            {
                int i = span[pos..].IndexOf(begin);
                if (i < 0)
                {
                    break;
                }

                int start = pos + i;
                // Decode ends at the block's own tail line; the next BEGIN bounds the slice so blocks cannot swallow each other.
                int next = span[(start + begin.Length)..].IndexOf(begin);
                ReadOnlySpan<byte> slice = next < 0 ? span[start..] : span.Slice(start, begin.Length + next);
                if (Armor.TryDecode(slice, out ArmorBlock? block, out OpenPgpFailure failure) && block!.Kind == ArmorKind.PublicKey)
                {
                    chunks.Add(block.Data);
                }
                else
                {
                    dropped.Add(new DiscoveryDrop("an armored block could not be decoded" + (block is null ? ": " + failure.Message : string.Empty), null));
                }

                pos = start + begin.Length;
            }
        }

        foreach (byte[] chunk in chunks)
        {
            IReadOnlyList<TransferableKey> keys;
            try
            {
                keys = TransferableKey.ParseAll(PacketParser.ParseAll(chunk));
            }
            catch (FormatException e)
            {
                // One malformed packet makes the whole run unreadable: the packet layer does not resynchronise.
                dropped.Add(new DiscoveryDrop("key data could not be parsed: " + e.Message, null));
                continue;
            }

            foreach (TransferableKey k in keys)
            {
                if (k.IsSecret)
                {
                    dropped.Add(new DiscoveryDrop("secret key material in a discovery response is never accepted", FingerprintOf(k)));
                }
                else if (found.Count >= options.MaxCertificates)
                {
                    dropped.Add(new DiscoveryDrop($"more than {options.MaxCertificates} certificates in one response", FingerprintOf(k)));
                }
                else
                {
                    found.Add(k);
                }
            }
        }

        return found;
    }

    private static byte[]? FingerprintOf(TransferableKey k)
    {
        try
        {
            return k.Primary.GetFingerprint();
        }
        catch (FormatException)
        {
            return null;
        }
    }

    // A new key with the same primary key, subkeys and bindings, only the chosen User IDs, and (when asked) only the signatures that can matter for the queried key.
    private static TransferableKey Rebuild(TransferableKey key, IEnumerable<UserComponent> users, bool dropThirdParty, ref int removed)
    {
        var packets = new List<Packet> { key.Primary };
        byte[] fingerprint = key.Primary.GetFingerprint();
        byte[] keyId = key.Primary.GetKeyId();

        foreach (SignaturePacket s in key.DirectSignatures)
        {
            // A key revocation from a designated revoker is as good as the owner's, so it stays whoever made it.
            if (!dropThirdParty || s.Type == SignatureType.KeyRevocation || IsBy(s, fingerprint, keyId))
            {
                packets.Add(s);
            }
            else
            {
                removed++;
            }
        }

        packets.AddRange(key.PrimaryOtherPackets.Where(p => p is not TrustPacket));
        foreach (UserComponent u in users)
        {
            packets.Add(u.Identity);
            foreach (SignaturePacket s in u.Signatures)
            {
                if (!dropThirdParty || IsBy(s, fingerprint, keyId))
                {
                    packets.Add(s);
                }
                else
                {
                    removed++;
                }
            }

            packets.AddRange(u.OtherPackets.Where(p => p is not TrustPacket));
        }

        foreach (SubkeyComponent sk in key.Subkeys)
        {
            packets.Add(sk.Key);
            packets.AddRange(sk.Signatures);
            packets.AddRange(sk.OtherPackets.Where(p => p is not TrustPacket));
        }

        return TransferableKey.Parse(packets);
    }

    // The issuer is named by the signature itself (fingerprint or key ID); a signature that names nobody cannot be shown to be the owner's, so it counts as foreign.
    private static bool IsBy(SignaturePacket s, byte[] fingerprint, byte[] keyId)
    {
        if (s.IssuerFingerprint is { } f && f.Length > 1)
        {
            return f.Span[1..].SequenceEqual(fingerprint);
        }

        return s.IssuerKeyId is { } id && id.Span.SequenceEqual(keyId);
    }

    private static bool Matches(UserIdPacket id, (string Local, string Domain) want)
    {
        (string, string)? have = NormalizeAddress(AddrSpec(id.Text));
        return have is { } h && string.Equals(h.Item1, want.Local, StringComparison.OrdinalIgnoreCase) && h.Item2 == want.Domain;
    }

    // "Name (comment) <addr>" or a bare "addr". Anything else is not a mailbox.
    private static string AddrSpec(string userId)
    {
        int lt = userId.LastIndexOf('<');
        int gt = userId.LastIndexOf('>');
        if (lt >= 0 && gt > lt)
        {
            return userId[(lt + 1)..gt].Trim();
        }

        string t = userId.Trim();
        return t.Contains(' ', StringComparison.Ordinal) ? string.Empty : t;
    }

    private static (string Local, string Domain)? NormalizeAddress(string address)
    {
        int at = address.LastIndexOf('@');
        if (at <= 0 || at == address.Length - 1 || address.Length > 320)
        {
            return null;
        }

        string domain = address[(at + 1)..].TrimEnd('.');
        if (domain.Any(c => c > 0x7F))
        {
            try
            {
                domain = new IdnMapping().GetAscii(domain);
            }
            catch (ArgumentException)
            {
                return null;
            }
        }

        return (address[..at], domain.ToLowerInvariant());
    }
}
