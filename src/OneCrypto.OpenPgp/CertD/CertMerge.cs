using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.CertD;

/// <summary>
/// The merge the shared certificate directory applies on insert: the union of two copies of one certificate. Components and signatures that
/// the stored copy already has stay exactly as stored; those only the new copy has are appended in the new copy's order. Nothing is
/// re-encoded, so every kept packet keeps its original bytes and a copy that adds nothing leaves the stored certificate unchanged.
/// </summary>
public static class CertMerge
{
    /// <summary>
    /// Merges <paramref name="incoming"/> into <paramref name="existing"/>. The two must have the same primary key. Trust packets of the incoming
    /// copy are dropped (they belong to the keyring they came from); those of the stored copy are kept.
    /// </summary>
    /// <param name="existing">The stored certificate, or null when there is none (the result is then the incoming certificate without trust packets).</param>
    /// <param name="incoming">The certificate being inserted.</param>
    /// <param name="changed">True when the result differs from <paramref name="existing"/>; always true when there is none.</param>
    /// <returns>The merged certificate.</returns>
    /// <exception cref="ArgumentException">The primary keys differ.</exception>
    public static TransferableKey Merge(TransferableKey? existing, TransferableKey incoming, out bool changed)
    {
        ArgumentNullException.ThrowIfNull(incoming);
        if (existing is null)
        {
            changed = true;
            return StripTrust(incoming);
        }

        if (!existing.Primary.GetFingerprint().AsSpan().SequenceEqual(incoming.Primary.GetFingerprint())) // public data
        {
            throw new ArgumentException("The certificates have different primary keys.", nameof(incoming));
        }

        var packets = new List<Packet>(existing.Packets);
        changed = false;

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (SignaturePacket s in existing.DirectSignatures)
        {
            seen.Add(Identity(s));
        }

        int insertAt = IndexAfterDirect(packets, existing);
        foreach (SignaturePacket s in incoming.DirectSignatures)
        {
            if (seen.Add(Identity(s)))
            {
                packets.Insert(insertAt++, s);
                changed = true;
            }
        }

        foreach (UserComponent u in incoming.Users)
        {
            UserComponent? have = existing.Users.FirstOrDefault(x => SameBody(x.Identity, u.Identity));
            if (have is null)
            {
                // RFC 9580 §10.1: user IDs come before the first subkey.
                int userAt = packets.FindIndex(p => p.TagId is (byte)PacketTag.PublicSubkey or (byte)PacketTag.SecretSubkey);
                if (userAt < 0)
                {
                    userAt = packets.Count;
                }

                packets.Insert(userAt, u.Identity);
                packets.InsertRange(userAt + 1, u.Signatures);
                changed = true;
                continue;
            }

            if (AddSignatures(packets, have.Identity, have.Signatures, u.Signatures))
            {
                changed = true;
            }
        }

        foreach (SubkeyComponent sk in incoming.Subkeys)
        {
            SubkeyComponent? have = existing.Subkeys.FirstOrDefault(x => x.Key.GetFingerprint().AsSpan().SequenceEqual(sk.Key.GetFingerprint())); // public data
            if (have is null)
            {
                packets.Add(sk.Key);
                packets.AddRange(sk.Signatures);
                changed = true;
                continue;
            }

            if (AddSignatures(packets, have.Key, have.Signatures, sk.Signatures))
            {
                changed = true;
            }
        }

        return changed ? TransferableKey.Parse(packets) : existing;
    }

    /// <summary>Returns the certificate without its trust packets, as the directory stores it.</summary>
    /// <param name="key">The certificate.</param>
    public static TransferableKey StripTrust(TransferableKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (!key.Packets.Any(p => p.TagId == (byte)PacketTag.Trust))
        {
            return key;
        }

        return TransferableKey.Parse(key.Packets.Where(p => p.TagId != (byte)PacketTag.Trust).ToList());
    }

    // Adds the signatures of the incoming component that the stored component lacks, right after the stored component's last signature.
    private static bool AddSignatures(List<Packet> packets, Packet owner, IReadOnlyList<SignaturePacket> have, IReadOnlyList<SignaturePacket> add)
    {
        var seen = new HashSet<string>(have.Select(Identity), StringComparer.Ordinal);
        int at = packets.IndexOf(owner) + 1;
        foreach (SignaturePacket s in have)
        {
            int i = packets.IndexOf(s);
            if (i >= at)
            {
                at = i + 1;
            }
        }

        bool any = false;
        foreach (SignaturePacket s in add)
        {
            if (seen.Add(Identity(s)))
            {
                packets.Insert(at++, s);
                any = true;
            }
        }

        return any;
    }

    private static int IndexAfterDirect(List<Packet> packets, TransferableKey existing)
    {
        int at = 1;
        foreach (SignaturePacket s in existing.DirectSignatures)
        {
            at = Math.Max(at, packets.IndexOf(s) + 1);
        }

        return at;
    }

    private static bool SameBody(Packet a, Packet b) => a.TagId == b.TagId && a.Body.Span.SequenceEqual(b.Body.Span); // public data

    // A signature is the same signature when everything it covers and its values agree; the unhashed subpackets are not part of that, since
    // anyone may add to them without invalidating it.
    private static string Identity(SignaturePacket s)
    {
        using var ms = new MemoryStream();
        ms.Write(s.SignedHeader.Span);
        ms.Write(s.HashPrefix.Span);
        ms.Write(s.Salt.Span);
        ms.Write(s.Material.Raw.Span);
        return Convert.ToHexString(ms.ToArray());
    }
}
