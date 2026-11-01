using System.Globalization;
using System.Text;
using RecursiveAI.OneCrypto.OpenPgp;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.Cli.Sop;

/// <summary>
/// generate-key, change-key-password, revoke-key, update-key, merge-certs, certify-userid and validate-userid
/// (draft-dkg-openpgp-stateless-cli §5.2, §5.3).
/// </summary>
internal static class KeyCommands
{
    // The tool's reference time is the system clock: the draft defines "now" that way. Library calls take the time explicitly.
    private static DateTimeOffset Now() => TimeProvider.System.GetUtcNow();

    /// <summary>The profiles generate-key accepts; the first is the default (draft §7.12).</summary>
    internal static readonly (string Name, string Description, PgpKeyProfile Profile)[] Profiles =
    [
        ("default", "use the implementer's recommendations: version 6 Ed25519/X25519 keys (RFC 9580)", PgpKeyProfile.Rfc9580),
        ("rfc9580", "version 6 Ed25519 and X25519 keys", PgpKeyProfile.Rfc9580),
        ("rfc9580-v4", "version 4 keys with the native Ed25519 and X25519 algorithms", PgpKeyProfile.Rfc9580V4),
        ("rfc9580-ed448", "version 6 Ed448 and X448 keys", PgpKeyProfile.Rfc9580Ed448),
        ("rfc9580-rsa", "version 6 keys with RSA-3072", PgpKeyProfile.Rfc9580Rsa),
        ("rfc4880", "version 4 keys with RSA-3072, readable by RFC 4880 implementations (alias: compatibility)", PgpKeyProfile.Rfc4880Rsa),
        ("compatibility", "alias for rfc4880", PgpKeyProfile.Rfc4880Rsa),
        ("draft-koch-eddsa-for-openpgp-00", "version 4 EdDSA (legacy) and ECDH Curve25519 keys", PgpKeyProfile.Rfc4880Curve25519),
        ("nist-p256", "version 4 ECDSA and ECDH keys on NIST P-256", PgpKeyProfile.NistP256),
        ("nist-p384", "version 4 ECDSA and ECDH keys on NIST P-384", PgpKeyProfile.NistP384),
        ("nist-p521", "version 4 ECDSA and ECDH keys on NIST P-521", PgpKeyProfile.NistP521),
        ("security", "higher security, maybe reduced performance: version 6 Ed448 and X448 keys", PgpKeyProfile.Rfc9580Ed448),
        ("performance", "higher performance, maybe reduced security: version 6 Ed25519 and X25519 keys", PgpKeyProfile.Rfc9580),
        ("pqc", "version 6 ML-DSA-65 + Ed25519 and ML-KEM-768 + X25519 keys (RFC 9980; needs platform support)", PgpKeyProfile.Rfc9980Pqc),
        ("pqc-high", "version 6 ML-DSA-87 + Ed448 and ML-KEM-1024 + X448 keys (RFC 9980; needs platform support)", PgpKeyProfile.Rfc9980PqcHigh),
    ];

    internal static string ProfileList() => string.Concat(Profiles.Select(p => p.Name + ": " + p.Description + "\n"));

    // ---- shared input and output ----

    private static List<PgpCertificate> ReadStdinCerts(SopIo io, bool secret)
    {
        using Stream binary = PacketCommands.OpenBinary(io.Stdin, out _);
        IReadOnlyList<TransferableKey> keys = TransferableKey.ParseAll(PacketParser.ParseAll(binary));
        if (keys.Count == 0)
        {
            throw new SopException(SopExit.BadData, "no keys in the input");
        }

        if (secret && keys.Any(k => !k.IsSecret))
        {
            throw new SopException(SopExit.BadData, "the input holds a certificate where a secret key is needed");
        }

        return keys.Select(PgpCertificate.FromTransferable).ToList();
    }

    private static void WriteKeys(SopIo io, IEnumerable<PgpCertificate> certs, bool secret, bool noArmor)
    {
        using var buffer = new MemoryStream();
        ArmorWriteStream? armor = noArmor ? null : new ArmorWriteStream(buffer, secret ? "PGP PRIVATE KEY BLOCK" : "PGP PUBLIC KEY BLOCK", leaveOpen: true);
        try
        {
            Stream target = (Stream?)armor ?? buffer;
            foreach (PgpCertificate c in certs)
            {
                (secret ? c.Transferable : c.Transferable.ToPublic()).WriteTo(target);
            }

            armor?.Complete();
        }
        finally
        {
            armor?.Dispose();
        }

        // Nothing is written to standard output until the whole result exists, so a failure leaves it empty.
        buffer.WriteTo(io.Stdout);
    }

    // §11.8: a password is read as text with trailing white space removed. New passwords must be text.
    private static byte[]? NewPassword(Options o, SopIo io, string option)
    {
        string? d = o.Value(option);
        if (d is null)
        {
            return null;
        }

        byte[] raw;
        using (Stream s = io.OpenInput(d))
        {
            raw = MessageCommands.ReadAll(s);
        }

        try
        {
            return Encoding.UTF8.GetBytes(new UTF8Encoding(false, true).GetString(raw).TrimEnd());
        }
        catch (ArgumentException)
        {
            throw new SopException(SopExit.PasswordNotHumanReadable, "the password is not valid UTF-8");
        }
    }

    private static PgpSecretKey UnlockPrimary(PgpCertificate cert, List<byte[]> passwords)
    {
        try
        {
            return PgpSecretKey.Unlock(cert.Primary, passwords);
        }
        catch (PgpException e) when (e.Failure == PgpFailure.KeyIsProtected)
        {
            throw new SopException(SopExit.KeyIsProtected, "the key is protected: " + Convert.ToHexString(cert.Fingerprint));
        }
        catch (PgpException e) when (e.Failure == PgpFailure.KeyCannotPerform)
        {
            throw new SopException(SopExit.BadData, "the primary key has no secret part: " + Convert.ToHexString(cert.Fingerprint));
        }
    }

    // ---- generate-key ----

    public static int RunGenerateKey(Options o, SopIo io)
    {
        bool noArmor = o.Flag("--no-armor");
        bool signingOnly = o.Flag("--signing-only");
        string? profileName = o.Value("--profile");
        byte[]? password = NewPasswordFromKeyOption(o, io);
        o.RejectUnknown();
        PgpKeyProfile profile = PgpKeyProfile.Rfc9580;
        if (profileName is not null)
        {
            (string Name, string Description, PgpKeyProfile Profile) found = Profiles.FirstOrDefault(p => p.Name == profileName);
            if (found.Name is null)
            {
                throw new SopException(SopExit.UnsupportedProfile, $"unsupported profile '{profileName}'");
            }

            profile = found.Profile;
        }

        PgpCertificate cert = PgpKeyGenerator.Generate(new PgpKeyGenerationOptions
        {
            Now = Now(),
            UserIds = o.Positionals,
            Profile = profile,
            SigningOnly = signingOnly,
            Password = password,
        });
        WriteKeys(io, [cert], secret: true, noArmor);
        return SopExit.Ok;
    }

    // generate-key takes a single --with-key-password; the multi-valued reader would accept several.
    private static byte[]? NewPasswordFromKeyOption(Options o, SopIo io)
    {
        IReadOnlyList<string> given = o.Values("--with-key-password");
        if (given.Count == 0)
        {
            return null;
        }

        if (given.Count > 1)
        {
            throw new SopException(SopExit.UnsupportedOption, "--with-key-password is given more than once");
        }

        byte[] raw;
        using (Stream s = io.OpenInput(given[0]))
        {
            raw = MessageCommands.ReadAll(s);
        }

        try
        {
            return Encoding.UTF8.GetBytes(new UTF8Encoding(false, true).GetString(raw).TrimEnd());
        }
        catch (ArgumentException)
        {
            throw new SopException(SopExit.PasswordNotHumanReadable, "the password is not valid UTF-8");
        }
    }

    // ---- change-key-password ----

    public static int RunChangeKeyPassword(Options o, SopIo io)
    {
        bool noArmor = o.Flag("--no-armor");
        byte[]? newPassword = NewPassword(o, io, "--new-key-password");
        List<byte[]> old = MessageCommands.Passwords(o, io, "--old-key-password", false);
        o.RejectUnknown();
        o.NoPositionals();
        List<PgpCertificate> keys = ReadStdinCerts(io, secret: true);
        var result = keys.Select(k => PgpKeyEditor.SetPassword(k, old, newPassword)).ToList();
        WriteKeys(io, result, secret: true, noArmor);
        return SopExit.Ok;
    }

    // ---- revoke-key ----

    public static int RunRevokeKey(Options o, SopIo io)
    {
        bool noArmor = o.Flag("--no-armor");
        List<byte[]> pws = MessageCommands.Passwords(o, io, "--with-key-password", false);
        o.RejectUnknown();
        o.NoPositionals();
        List<PgpCertificate> keys = ReadStdinCerts(io, secret: true);
        DateTimeOffset now = Now();
        var result = new List<PgpCertificate>();
        foreach (PgpCertificate k in keys)
        {
            using PgpSecretKey primary = UnlockPrimary(k, pws);
            result.Add(PgpKeyEditor.RevokeKey(k.ToPublicCertificate(), primary, PgpRevocationReason.None, string.Empty, now));
        }

        WriteKeys(io, result, secret: false, noArmor);
        return SopExit.Ok;
    }

    // ---- update-key ----

    public static int RunUpdateKey(Options o, SopIo io)
    {
        bool noArmor = o.Flag("--no-armor");
        bool signingOnly = o.Flag("--signing-only");
        bool noAdded = o.Flag("--no-added-capabilities");
        _ = o.Flag("--revoke-deprecated-keys"); // Only meaningful when a replacement key is generated, which this tool never does; the draft says to ignore it then.
        List<byte[]> pws = MessageCommands.Passwords(o, io, "--with-key-password", false);
        IReadOnlyList<string> mergeFiles = o.Values("--merge-certs");
        o.RejectUnknown();
        o.NoPositionals();
        List<PgpCertificate> keys = ReadStdinCerts(io, secret: true);
        List<PgpCertificate> others = MessageCommands.LoadCerts(o, io, mergeFiles, secret: false);
        DateTimeOffset now = Now();
        var result = new List<PgpCertificate>();
        foreach (PgpCertificate k in keys)
        {
            if (k.Primary.StateAt(now) is { IsValid: false, Reason: "The key is revoked." })
            {
                throw new SopException(SopExit.PrimaryKeyBad, "the primary key is revoked: " + Convert.ToHexString(k.Fingerprint));
            }

            // New components are protected like the rest, with the password that opens the primary key.
            byte[]? used = k.Primary.Packet is SecretKeyPacket { Protection.IsProtected: true } ? pws.FirstOrDefault(p => Opens(k.Primary, p)) : null;
            PgpCertificate updated;
            using (PgpSecretKey primary = UnlockPrimary(k, pws))
            {
                updated = PgpKeyEditor.Refresh(k, primary, now, signingOnly, noAdded);
            }

            if (used is not null)
            {
                updated = PgpKeyEditor.SetPassword(updated, pws, used);
            }

            foreach (PgpCertificate other in others.Where(c => c.Fingerprint.AsSpan().SequenceEqual(updated.Fingerprint)))
            {
                updated = PgpKeyEditor.Merge(updated, other);
            }

            result.Add(updated);
        }

        WriteKeys(io, result, secret: true, noArmor);
        return SopExit.Ok;
    }

    private static bool Opens(PgpKey key, byte[] password)
    {
        if (!PgpSecretKey.TryUnlock(key, [password], out PgpSecretKey? unlocked))
        {
            return false;
        }

        unlocked!.Dispose();
        return true;
    }

    // ---- merge-certs ----

    public static int RunMergeCerts(Options o, SopIo io)
    {
        bool noArmor = o.Flag("--no-armor");
        o.RejectUnknown();
        if (o.Positionals.Count == 0)
        {
            throw new SopException(SopExit.MissingArg, "merge-certs needs at least one CERTS argument");
        }

        List<PgpCertificate> input = ReadStdinCerts(io, secret: false);
        List<PgpCertificate> others = MessageCommands.LoadCerts(o, io, o.Positionals, secret: false);

        // Certificates on standard input that share a primary key are merged into one; the others only add to a certificate that is already there.
        var merged = new List<PgpCertificate>();
        foreach (PgpCertificate c in input)
        {
            int i = merged.FindIndex(m => m.Fingerprint.AsSpan().SequenceEqual(c.Fingerprint));
            if (i < 0)
            {
                merged.Add(c);
            }
            else
            {
                merged[i] = PgpKeyEditor.Merge(merged[i], c);
            }
        }

        for (int i = 0; i < merged.Count; i++)
        {
            foreach (PgpCertificate other in others.Where(c => c.Fingerprint.AsSpan().SequenceEqual(merged[i].Fingerprint)))
            {
                merged[i] = PgpKeyEditor.Merge(merged[i], other);
            }
        }

        WriteKeys(io, merged, secret: false, noArmor);
        return SopExit.Ok;
    }

    // ---- certify-userid ----

    public static int RunCertifyUserId(Options o, SopIo io)
    {
        bool noArmor = o.Flag("--no-armor");
        bool noRequireSelfSig = o.Flag("--no-require-self-sig");
        IReadOnlyList<string> userIds = o.Values("--userid");
        List<byte[]> pws = MessageCommands.Passwords(o, io, "--with-key-password", false);
        o.RejectUnknown();
        if (userIds.Count == 0)
        {
            throw new SopException(SopExit.MissingArg, "certify-userid needs at least one --userid");
        }

        if (o.Positionals.Count == 0)
        {
            throw new SopException(SopExit.MissingArg, "certify-userid needs at least one KEYS argument");
        }

        List<PgpCertificate> certifierKeys = MessageCommands.LoadCerts(o, io, o.Positionals, secret: true);
        List<PgpCertificate> certs = ReadStdinCerts(io, secret: false);
        DateTimeOffset now = Now();
        var unlocked = new List<PgpSecretKey>();
        try
        {
            foreach (PgpCertificate ck in certifierKeys)
            {
                PgpKeyState st = ck.Primary.StateAt(now);
                if (!st.IsValid || (st.Usage & PgpKeyUsage.Certify) == 0)
                {
                    throw new SopException(SopExit.KeyCannotCertify, "a key cannot certify: " + Convert.ToHexString(ck.Fingerprint));
                }

                unlocked.Add(UnlockPrimary(ck, pws));
            }

            var result = new List<PgpCertificate>();
            foreach (PgpCertificate cert in certs)
            {
                PgpCertificate c = cert;
                foreach (string uid in userIds)
                {
                    if (!noRequireSelfSig && !PgpUserIds.HasSelfSignature(c, uid, now))
                    {
                        throw new SopException(SopExit.CertUseridNoMatch, $"the certificate {Convert.ToHexString(c.Fingerprint)} has no self-signed User ID '{uid}'");
                    }

                    foreach (PgpSecretKey k in unlocked)
                    {
                        c = PgpKeyEditor.Certify(c, uid, k, now, requireSelfSignature: !noRequireSelfSig);
                    }
                }

                result.Add(c);
            }

            WriteKeys(io, result, secret: false, noArmor);
            return SopExit.Ok;
        }
        finally
        {
            foreach (PgpSecretKey k in unlocked)
            {
                k.Dispose();
            }
        }
    }

    // ---- validate-userid ----

    public static int RunValidateUserId(Options o, SopIo io)
    {
        bool addrSpec = o.Flag("--addr-spec-only");
        string? at = o.Value("--validate-at");
        o.RejectUnknown();
        if (o.Positionals.Count < 2)
        {
            throw new SopException(SopExit.MissingArg, "validate-userid needs a USERID and at least one CERTS argument");
        }

        DateTimeOffset when = Now();
        if (at is not null && at != "now")
        {
            if (!DateTimeOffset.TryParse(at, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out when))
            {
                throw new SopException(SopExit.UnsupportedOption, "cannot read the date " + at);
            }
        }

        string userId = o.Positionals[0];
        List<PgpCertificate> authorities = MessageCommands.LoadCerts(o, io, o.Positionals.Skip(1), secret: false);
        List<PgpCertificate> certs = ReadStdinCerts(io, secret: false);
        foreach (PgpCertificate c in certs)
        {
            if (!PgpUserIds.IsCertified(c, userId, authorities, when, addrSpec))
            {
                throw new SopException(SopExit.CertUseridNoMatch, $"no valid certification of '{userId}' on {Convert.ToHexString(c.Fingerprint)}");
            }
        }

        return SopExit.Ok;
    }
}
