using System.Security.Cryptography;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Policy;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>A running signature hash that can canonicalise text on the way in (RFC 9580 §5.2.1: type 0x01 hashes line endings as CR LF).</summary>
internal sealed class SigHasher : IDisposable
{
    private readonly IncrementalHash _h;
    private readonly bool _text;
    private bool _lastWasCr;

    internal SigHasher(PgpHashAlgorithm hash, ReadOnlySpan<byte> salt, bool text)
    {
        _h = SignatureEngine.Start(hash, salt);
        _text = text;
    }

    internal void Append(ReadOnlySpan<byte> data)
    {
        if (!_text)
        {
            _h.AppendData(data);
            return;
        }

        int start = 0;
        for (int i = 0; i < data.Length; i++)
        {
            byte b = data[i];
            if (b == (byte)'\n')
            {
                // A line feed after a carriage return is the second half of CR LF, already emitted; a bare one becomes CR LF.
                _h.AppendData(data[start..i]);
                if (!_lastWasCr)
                {
                    _h.AppendData("\r\n"u8);
                }

                start = i + 1;
                _lastWasCr = false;
            }
            else if (b == (byte)'\r')
            {
                _h.AppendData(data[start..i]);
                _h.AppendData("\r\n"u8);
                start = i + 1;
                _lastWasCr = true;
            }
            else
            {
                _lastWasCr = false;
            }
        }

        _h.AppendData(data[start..]);
    }

    internal byte[] Finish(byte version, ReadOnlySpan<byte> signedHeader) => SignatureEngine.Finish(_h, version, signedHeader);

    public void Dispose() => _h.Dispose();
}

/// <summary>Turns a signature, its digest and the supplied certificates into a <see cref="PgpSignatureResult"/>.</summary>
internal static class SignatureChecker
{
    internal static PgpSignatureResult Check(SignaturePacket sig, byte[]? digest, IReadOnlyList<PgpCertificate> certificates, CryptoPolicy policy, DateTimeOffset now)
    {
        var reasons = new List<string>();
        List<PgpKey> candidates = Find(sig, certificates);
        if (candidates.Count == 0)
        {
            reasons.Add("None of the supplied certificates contains the issuing key.");
            return new PgpSignatureResult(sig, PgpSignatureStatus.UnknownKey, null, null, reasons);
        }

        if (digest is null)
        {
            reasons.Add("The signature could not be matched to the signed data.");
            return new PgpSignatureResult(sig, PgpSignatureStatus.Invalid, candidates[0], null, reasons);
        }

        if (sig.CreationTime is not { } created)
        {
            reasons.Add("The signature has no creation time (RFC 9580 §5.2.3.11).");
            return new PgpSignatureResult(sig, PgpSignatureStatus.Invalid, candidates[0], null, reasons);
        }

        DateTimeOffset at = DateTimeOffset.FromUnixTimeSeconds(created);
        PolicyDecision hashDecision;
        try
        {
            hashDecision = policy.CheckHash(PgpAlgorithms.HashName(sig.Hash), CryptoUse.Verify, at);
        }
        catch (PgpException e)
        {
            reasons.Add(e.Message);
            return new PgpSignatureResult(sig, PgpSignatureStatus.Unsupported, candidates[0], null, reasons);
        }

        if (hashDecision.Verdict == PolicyVerdict.Rejected)
        {
            reasons.Add(hashDecision.Reason + " " + hashDecision.Reference);
            return new PgpSignatureResult(sig, PgpSignatureStatus.Rejected, candidates[0], hashDecision, reasons);
        }

        if (hashDecision.Verdict == PolicyVerdict.Flagged)
        {
            reasons.Add(hashDecision.Reason);
        }

        PgpSignatureStatus worst = PgpSignatureStatus.Invalid;
        PgpKey? tried = null;
        foreach (PgpKey k in candidates)
        {
            tried = k;
            PgpKeyState state = k.StateAt(at);
            if (!state.IsValid)
            {
                reasons.Add(state.Reason ?? "The key was not valid when the signature was made.");
                worst = PgpSignatureStatus.KeyNotValid;
                continue;
            }

            if ((state.Usage & PgpKeyUsage.Sign) == 0)
            {
                reasons.Add("The key's flags do not allow signing (RFC 9580 §5.2.3.29).");
                worst = PgpSignatureStatus.KeyNotValid;
                continue;
            }

            if (k.Packet.Material.IsKnown && k.Algorithm is PublicKeyAlgorithm.Rsa or PublicKeyAlgorithm.RsaSignOnly)
            {
                int bits = k.Packet.Material.Values[0].Length * 8;
                if (bits < policy.MinRsaBitsVerify)
                {
                    reasons.Add($"The RSA key has {bits} bits; the policy requires {policy.MinRsaBitsVerify}.");
                    worst = PgpSignatureStatus.Rejected;
                    continue;
                }
            }

            bool ok;
            try
            {
                ok = SignatureEngine.VerifyDigest(k.Packet, sig, digest);
            }
            catch (PgpException e)
            {
                reasons.Add(e.Message);
                return new PgpSignatureResult(sig, PgpSignatureStatus.Unsupported, k, hashDecision, reasons);
            }

            if (!ok)
            {
                continue;
            }

            if (created > (ulong)now.ToUnixTimeSeconds())
            {
                reasons.Add("The signature was made after the reference time.");
                return new PgpSignatureResult(sig, PgpSignatureStatus.KeyNotValid, k, hashDecision, reasons);
            }

            if (sig.ExpirationSeconds is { } exp and > 0 && (long)created + exp <= now.ToUnixTimeSeconds())
            {
                reasons.Add("The signature has expired (RFC 9580 §5.2.3.18).");
                return new PgpSignatureResult(sig, PgpSignatureStatus.KeyNotValid, k, hashDecision, reasons);
            }

            return new PgpSignatureResult(sig, PgpSignatureStatus.Valid, k, hashDecision, reasons);
        }

        if (worst == PgpSignatureStatus.Invalid)
        {
            reasons.Add("The signature does not match the data.");
        }

        return new PgpSignatureResult(sig, worst, tried, hashDecision, reasons);
    }

    private static List<PgpKey> Find(SignaturePacket sig, IReadOnlyList<PgpCertificate> certificates)
    {
        var found = new List<PgpKey>();
        foreach (PgpCertificate c in certificates)
        {
            foreach (PgpKey k in c.Keys)
            {
                if (Matches(sig, k))
                {
                    found.Add(k);
                }
            }
        }

        return found;
    }

    internal static bool Matches(SignaturePacket sig, PgpKey k)
    {
        bool algorithmOk = sig.Algorithm == k.Algorithm || (sig.Algorithm is PublicKeyAlgorithm.Rsa or PublicKeyAlgorithm.RsaSignOnly && k.Algorithm is PublicKeyAlgorithm.Rsa or PublicKeyAlgorithm.RsaSignOnly);
        if (!algorithmOk)
        {
            return false;
        }

        if (sig.IssuerFingerprint is { } fp && fp.Length > 1)
        {
            return fp.Span[1..].SequenceEqual(k.Fingerprint);
        }

        return sig.IssuerKeyId is { } id && id.Span.SequenceEqual(k.KeyId);
    }
}
