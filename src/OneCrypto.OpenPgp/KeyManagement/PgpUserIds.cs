using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>Questions about the User IDs of a certificate and who vouches for them (RFC 9580 §5.2.1.3, §10.1).</summary>
public static class PgpUserIds
{
    /// <summary>
    /// True when <paramref name="cert"/> has a User ID matching <paramref name="userId"/> that one of the <paramref name="authorities"/> has certified, judged at
    /// <paramref name="at"/>. The certification must verify against the authority's primary key, have been made by then and not be expired, and the authority's
    /// key must be valid then. A later revocation of the certification by the same authority, or a revocation of the User ID by the certificate's own key,
    /// ends it. The certificate's primary key must be valid at that time too.
    /// </summary>
    /// <param name="cert">The certificate whose User ID is in question.</param>
    /// <param name="userId">The User ID text; with <paramref name="addrSpecOnly"/>, an e-mail address that is matched against the address part of each User ID.</param>
    /// <param name="authorities">Certificates whose primary keys may certify.</param>
    /// <param name="at">The reference time. There is no default clock.</param>
    /// <param name="addrSpecOnly">True to compare only the address in angle brackets (or a bare address), ignoring case.</param>
    public static bool IsCertified(PgpCertificate cert, string userId, IReadOnlyList<PgpCertificate> authorities, DateTimeOffset at, bool addrSpecOnly = false)
    {
        ArgumentNullException.ThrowIfNull(cert);
        ArgumentNullException.ThrowIfNull(userId);
        ArgumentNullException.ThrowIfNull(authorities);
        if (!cert.Primary.StateAt(at).IsValid)
        {
            return false;
        }

        KeyPacket target = cert.Primary.Packet;
        byte[] pk = SignatureEngine.KeyInput(target);
        long now = at.ToUnixTimeSeconds();
        foreach (UserComponent u in cert.Transferable.Users)
        {
            if (u.Identity is not UserIdPacket id || !Matches(id.Text, userId, addrSpecOnly))
            {
                continue;
            }

            byte[] uid = SignatureEngine.UserIdInput(u.Identity);
            bool selfRevoked = u.Signatures.Any(s => s.Type == SignatureType.CertificationRevocation && (s.CreationTime ?? 0) <= now
                && PgpKeyEditor.IssuedBy(s, target) && PgpKeyEditor.Verifies(s, target, pk, uid));
            if (selfRevoked)
            {
                continue;
            }

            foreach (PgpCertificate authority in authorities)
            {
                KeyPacket ak = authority.Primary.Packet;
                foreach (SignaturePacket s in u.Signatures)
                {
                    bool isCert = s.Type is SignatureType.GenericCertification or SignatureType.PersonaCertification or SignatureType.CasualCertification or SignatureType.PositiveCertification;
                    long t = s.CreationTime ?? 0;
                    if (!isCert || t > now || (s.ExpirationSeconds is { } e and > 0 && t + e <= now) || !PgpKeyEditor.IssuedBy(s, ak) || !PgpKeyEditor.Verifies(s, ak, pk, uid))
                    {
                        continue;
                    }

                    PgpKeyState state = authority.Primary.StateAt(at);
                    if (!state.IsValid || (state.Usage & PgpKeyUsage.Certify) == 0)
                    {
                        continue;
                    }

                    bool revoked = u.Signatures.Any(r => r.Type == SignatureType.CertificationRevocation && (r.CreationTime ?? 0) >= t && (r.CreationTime ?? 0) <= now
                        && PgpKeyEditor.IssuedBy(r, ak) && PgpKeyEditor.Verifies(r, ak, pk, uid));
                    if (!revoked)
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /// <summary>
    /// True when the certificate has a User ID with exactly this text that its own primary key certified (RFC 9580 §5.2.1.3), the certification being made by <paramref name="at"/>
    /// and not expired or revoked by the same key since.
    /// </summary>
    public static bool HasSelfSignature(PgpCertificate cert, string userId, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(cert);
        ArgumentNullException.ThrowIfNull(userId);
        return IsCertified(cert, userId, [cert], at);
    }

    // RFC 5322 name-addr: the address is the text between the last '<' and the following '>'. A User ID without brackets is not a conventional one and never matches.
    private static bool Matches(string stored, string wanted, bool addrSpecOnly)
    {
        if (!addrSpecOnly)
        {
            return string.Equals(stored, wanted, StringComparison.Ordinal);
        }

        int lt = stored.LastIndexOf('<');
        int gt = stored.LastIndexOf('>');
        if (lt < 0 || gt < lt)
        {
            return false;
        }

        return string.Equals(stored.Substring(lt + 1, gt - lt - 1), wanted, StringComparison.OrdinalIgnoreCase);
    }
}
