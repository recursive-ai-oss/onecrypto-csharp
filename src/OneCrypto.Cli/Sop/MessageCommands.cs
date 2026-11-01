using System.Globalization;
using System.Text;
using RecursiveAI.OneCrypto.OpenPgp;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.Cli.Sop;

/// <summary>sign, verify, inline-sign, inline-verify, encrypt and decrypt (draft-dkg-openpgp-stateless-cli §5.4).</summary>
internal static class MessageCommands
{
    // The tool's reference time is the system clock: the draft defines "now" that way (§5.4.2). Library calls take the time explicitly.
    private static DateTimeOffset Now() => TimeProvider.System.GetUtcNow();

    // ---- argument helpers ----

    private static byte[] ReadAll(Stream s)
    {
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }

    private static List<PgpCertificate> LoadCerts(Options o, SopIo io, IEnumerable<string> designators, bool secret)
    {
        var list = new List<PgpCertificate>();
        foreach (string d in designators)
        {
            byte[] data;
            using (Stream s = io.OpenInput(d))
            {
                data = ReadAll(s);
            }

            IReadOnlyList<PgpCertificate> certs;
            try
            {
                certs = PgpCertificate.ParseAll(data);
            }
            catch (OpenPgpParseException e)
            {
                throw new SopException(SopExit.BadData, $"{d} is not a valid OpenPGP {(secret ? "key" : "certificate")}: {e.Message}");
            }

            if (certs.Count == 0)
            {
                throw new SopException(SopExit.BadData, $"{d} holds no {(secret ? "key" : "certificate")}");
            }

            foreach (PgpCertificate c in certs)
            {
                if (secret && !c.HasSecretKeyMaterial)
                {
                    throw new SopException(SopExit.BadData, $"{d} holds a certificate where a secret key is needed");
                }

                list.Add(c);
            }
        }

        _ = o;
        return list;
    }

    private static List<byte[]> Passwords(Options o, SopIo io, string option, bool requireText)
    {
        var list = new List<byte[]>();
        foreach (string d in o.Values(option))
        {
            byte[] raw;
            using (Stream s = io.OpenInput(d))
            {
                raw = ReadAll(s);
            }

            // §11.8: trailing whitespace is trimmed; a password that is not UTF-8 is refused for a new message.
            string text;
            try
            {
                text = new UTF8Encoding(false, true).GetString(raw);
            }
            catch (ArgumentException)
            {
                if (requireText)
                {
                    throw new SopException(SopExit.PasswordNotHumanReadable, "the password is not valid UTF-8");
                }

                list.Add(raw);
                continue;
            }

            list.Add(Encoding.UTF8.GetBytes(text.TrimEnd()));
            if (!requireText && text.TrimEnd() != text)
            {
                list.Add(raw);
            }
        }

        return list;
    }

    private static DateTimeOffset? ParseDate(string? v, bool upper)
    {
        if (v is null)
        {
            return upper ? Now() : null;
        }

        if (v == "-")
        {
            return null;
        }

        if (DateTimeOffset.TryParse(v, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset t))
        {
            return t;
        }

        throw new SopException(SopExit.UnsupportedOption, "cannot read the date " + v);
    }

    private static SpoolForSop? ValidatedText(Options o, Stream input, bool text)
    {
        _ = o;
        if (!text)
        {
            return null;
        }

        // §5.4.1: with --as=text the data must be UTF-8; it is spooled while it is checked so the signature pass can read it again.
        var spool = new SpoolForSop();
        var dec = new UTF8Encoding(false, true).GetDecoder();
        byte[] buf = new byte[64 * 1024];
        char[] chars = new char[buf.Length + 4];
        int n;
        try
        {
            while ((n = input.Read(buf, 0, buf.Length)) > 0)
            {
                dec.GetChars(buf, 0, n, chars, 0, false);
                spool.Stream.Write(buf, 0, n);
            }

            dec.GetChars([], 0, 0, chars, 0, true);
        }
        catch (ArgumentException)
        {
            spool.Dispose();
            throw new SopException(SopExit.ExpectedText, "the input is not valid UTF-8");
        }

        spool.Stream.Position = 0;
        return spool;
    }

    private sealed class SpoolForSop : Stream
    {
        private readonly FileStream _file;

        internal SpoolForSop()
        {
            string path = Path.Combine(Path.GetTempPath(), "onecrypto-sop-" + Guid.NewGuid().ToString("N"));
            _file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 1 << 16, FileOptions.DeleteOnClose);
        }

        internal Stream Stream => _file;

        public override bool CanRead => true;

        public override bool CanSeek => true;

        public override bool CanWrite => true;

        public override long Length => _file.Length;

        public override long Position
        {
            get => _file.Position;
            set => _file.Position = value;
        }

        public override int Read(byte[] buffer, int offset, int count) => _file.Read(buffer, offset, count);

        public override void Write(byte[] buffer, int offset, int count) => _file.Write(buffer, offset, count);

        public override void Flush() => _file.Flush();

        public override long Seek(long offset, SeekOrigin origin) => _file.Seek(offset, origin);

        public override void SetLength(long value) => _file.SetLength(value);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _file.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    private static List<PgpSecretKey> UnlockSigners(List<PgpCertificate> keys, List<byte[]> keyPasswords, DateTimeOffset now)
    {
        var signers = new List<PgpSecretKey>();
        try
        {
            foreach (PgpCertificate c in keys)
            {
                PgpKey? k = c.FindSigningKey(now) ?? throw new SopException(SopExit.KeyCannotSign, "a key cannot sign: " + Convert.ToHexString(c.Fingerprint));
                try
                {
                    signers.Add(PgpSecretKey.Unlock(k, keyPasswords));
                }
                catch (PgpException e) when (e.Failure == PgpFailure.KeyIsProtected)
                {
                    throw new SopException(SopExit.KeyIsProtected, "the key is protected: " + Convert.ToHexString(c.Fingerprint));
                }
                catch (PgpException e) when (e.Failure == PgpFailure.KeyCannotPerform)
                {
                    throw new SopException(SopExit.KeyCannotSign, e.Message);
                }
            }
        }
        catch
        {
            foreach (PgpSecretKey s in signers)
            {
                s.Dispose();
            }

            throw;
        }

        return signers;
    }

    private static string AsMode(Options o, params string[] allowed)
    {
        string v = o.Value("--as") ?? "binary";
        return Array.IndexOf(allowed, v) >= 0 ? v : throw new SopException(SopExit.UnsupportedOption, "unsupported --as value " + v);
    }

    private static void WriteVerifications(Stream? target, PgpReadResult r, DateTimeOffset? notBefore, DateTimeOffset? notAfter)
    {
        if (target is null)
        {
            return;
        }

        var sb = new StringBuilder();
        foreach (PgpSignatureResult s in Accepted(r, notBefore, notAfter))
        {
            string mode = s.Signature.Type == SignatureType.Text ? "text" : "binary";
            sb.Append(s.CreatedAt!.Value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)).Append(' ')
              .Append(Convert.ToHexString(s.Signer!.Fingerprint)).Append(' ')
              .Append(Convert.ToHexString(s.Signer.Certificate.Fingerprint)).Append(" mode:").Append(mode).Append('\n');
        }

        target.Write(Encoding.UTF8.GetBytes(sb.ToString()));
    }

    private static IEnumerable<PgpSignatureResult> Accepted(PgpReadResult r, DateTimeOffset? notBefore, DateTimeOffset? notAfter) =>
        r.Signatures.Where(s => s.IsValid && s.CreatedAt is { } t && (notBefore is null || t >= notBefore) && (notAfter is null || t <= notAfter));

    // ---- sign ----

    internal static int RunSign(Options o, SopIo io)
    {
        bool noArmor = o.Flag("--no-armor");
        string? micalg = o.Value("--micalg-out");
        List<byte[]> keyPw = Passwords(o, io, "--with-key-password", false);
        string mode = AsMode(o, "binary", "text");
        o.RejectUnknown();
        if (o.Positionals.Count == 0)
        {
            throw new SopException(SopExit.MissingArg, "sign needs at least one key");
        }

        DateTimeOffset now = Now();
        List<PgpCertificate> keys = LoadCerts(o, io, o.Positionals, secret: true);
        List<PgpSecretKey> signers = UnlockSigners(keys, keyPw, now);
        Stream? micOut = micalg is null ? null : SopIo.OpenOutput(micalg);
        try
        {
            using Stream? spool = ValidatedText(o, io.Stdin, mode == "text");
            Stream data = spool ?? io.Stdin;
            IReadOnlyList<PgpHashAlgorithm> hashes = PgpMessageWriter.SignDetached(data, io.Stdout, new PgpWriteOptions { Now = now, Signers = signers, Text = mode == "text", Armor = !noArmor });
            if (micOut is not null)
            {
                string m = hashes.Distinct().Count() == 1 ? "pgp-" + PgpMessageWriter.HashHeaderName(hashes[0]).ToLowerInvariant() : string.Empty;
                micOut.Write(Encoding.ASCII.GetBytes(m));
            }
        }
        finally
        {
            micOut?.Dispose();
            foreach (PgpSecretKey s in signers)
            {
                s.Dispose();
            }
        }

        return SopExit.Ok;
    }

    // ---- verify ----

    internal static int RunVerify(Options o, SopIo io)
    {
        DateTimeOffset? before = ParseDate(o.Value("--not-before"), false);
        DateTimeOffset? after = ParseDate(o.Value("--not-after"), true);
        o.RejectUnknown();
        if (o.Positionals.Count < 2)
        {
            throw new SopException(SopExit.MissingArg, "verify needs SIGNATURES and at least one CERTS");
        }

        byte[] sigs;
        using (Stream s = io.OpenInput(o.Positionals[0]))
        {
            sigs = ReadAll(s);
        }

        List<PgpCertificate> certs = LoadCerts(o, io, o.Positionals.Skip(1), secret: false);
        PgpReadResult r;
        try
        {
            r = PgpMessageReader.VerifyDetached(io.Stdin, new MemoryStream(sigs), new PgpReadOptions { Now = Now(), Certificates = certs });
        }
        catch (PgpException e) when (e.Failure == PgpFailure.MalformedMessage)
        {
            throw new SopException(SopExit.BadData, e.Message);
        }

        return Finish(r, io.Stdout, before, after);
    }

    private static int Finish(PgpReadResult r, Stream verifications, DateTimeOffset? before, DateTimeOffset? after)
    {
        if (!Accepted(r, before, after).Any())
        {
            return SopExit.NoSignature;
        }

        WriteVerifications(verifications, r, before, after);
        return SopExit.Ok;
    }

    // ---- inline-sign / inline-verify ----

    internal static int RunInlineSign(Options o, SopIo io)
    {
        bool noArmor = o.Flag("--no-armor");
        List<byte[]> keyPw = Passwords(o, io, "--with-key-password", false);
        string mode = AsMode(o, "binary", "text", "clearsigned");
        o.RejectUnknown();
        if (o.Positionals.Count == 0)
        {
            throw new SopException(SopExit.MissingArg, "inline-sign needs at least one key");
        }

        if (noArmor && mode == "clearsigned")
        {
            throw new SopException(SopExit.IncompatibleOptions, "--no-armor cannot be combined with --as=clearsigned");
        }

        DateTimeOffset now = Now();
        List<PgpCertificate> keys = LoadCerts(o, io, o.Positionals, secret: true);
        List<PgpSecretKey> signers = UnlockSigners(keys, keyPw, now);
        try
        {
            using Stream? spool = ValidatedText(o, io.Stdin, mode != "binary");
            Stream data = spool ?? io.Stdin;
            var w = new PgpWriteOptions { Now = now, Signers = signers, Text = mode != "binary", Armor = !noArmor };
            if (mode == "clearsigned")
            {
                PgpMessageWriter.SignCleartext(data, io.Stdout, w);
            }
            else
            {
                PgpMessageWriter.Write(data, io.Stdout, w);
            }
        }
        finally
        {
            foreach (PgpSecretKey s in signers)
            {
                s.Dispose();
            }
        }

        return SopExit.Ok;
    }

    internal static int RunInlineVerify(Options o, SopIo io)
    {
        DateTimeOffset? before = ParseDate(o.Value("--not-before"), false);
        DateTimeOffset? after = ParseDate(o.Value("--not-after"), true);
        string? vout = o.Value("--verifications-out");
        o.RejectUnknown();
        if (o.Positionals.Count == 0)
        {
            throw new SopException(SopExit.MissingArg, "inline-verify needs at least one CERTS");
        }

        List<PgpCertificate> certs = LoadCerts(o, io, o.Positionals, secret: false);
        var opts = new PgpReadOptions { Now = Now(), Certificates = certs, Require = PgpRequirement.NotEncrypted };
        // Nothing is emitted unless a signature verifies, so the plaintext is held until the verdict is known.
        using var held = new MemoryStream();
        PgpReadResult r;
        try
        {
            r = PgpMessageReader.ReadSigned(io.Stdin, held, opts);
        }
        catch (PgpException e)
        {
            throw new SopException(SopExit.BadData, e.Message);
        }

        if (!Accepted(r, before, after).Any())
        {
            return SopExit.NoSignature;
        }

        io.Stdout.Write(held.GetBuffer(), 0, (int)held.Length);
        if (vout is not null)
        {
            using Stream v = SopIo.OpenOutput(vout);
            WriteVerifications(v, r, before, after);
        }

        return SopExit.Ok;
    }

    // ---- encrypt ----

    internal static int RunEncrypt(Options o, SopIo io)
    {
        string mode = AsMode(o, "binary", "text");
        bool noArmor = o.Flag("--no-armor");
        List<byte[]> pw = Passwords(o, io, "--with-password", true);
        IReadOnlyList<string> signWith = o.Values("--sign-with");
        List<byte[]> keyPw = Passwords(o, io, "--with-key-password", false);
        string? profile = o.Value("--profile");
        string? sessionOut = o.Value("--session-key-out");
        string forUse = o.Value("--for") ?? "any";
        o.RejectUnknown();
        if (profile is not (null or "rfc9580" or "rfc4880"))
        {
            throw new SopException(SopExit.UnsupportedProfile, "unknown profile " + profile);
        }

        if (forUse is not ("any" or "storage" or "communications"))
        {
            throw new SopException(SopExit.UnsupportedOption, "unsupported --for value " + forUse);
        }

        if (o.Positionals.Count == 0 && pw.Count == 0)
        {
            throw new SopException(SopExit.MissingArg, "encrypt needs recipients or a password");
        }

        DateTimeOffset now = Now();
        List<PgpCertificate> recipients = LoadCerts(o, io, o.Positionals, secret: false);
        List<PgpSecretKey> signers = UnlockSigners(LoadCerts(o, io, signWith, secret: true), keyPw, now);
        Stream? keyOut = sessionOut is null ? null : SopIo.OpenOutput(sessionOut);
        try
        {
            using Stream? spool = ValidatedText(o, io.Stdin, mode == "text");
            Stream data = spool ?? io.Stdin;
            var w = new PgpWriteOptions
            {
                Now = now,
                Recipients = recipients,
                Passwords = pw,
                Signers = signers,
                Text = mode == "text",
                Armor = !noArmor,
                ForceSeipd1 = profile == "rfc4880",
                OnSessionKey = keyOut is null ? null : (c, k) => keyOut.Write(Encoding.ASCII.GetBytes($"{(byte)c}:{Convert.ToHexString(k)}\n")),
            };
            PgpMessageWriter.Write(data, io.Stdout, w);
        }
        catch (PgpException e) when (e.Failure == PgpFailure.KeyCannotPerform)
        {
            throw new SopException(SopExit.CertCannotEncrypt, e.Message);
        }
        finally
        {
            keyOut?.Dispose();
            foreach (PgpSecretKey s in signers)
            {
                s.Dispose();
            }
        }

        return SopExit.Ok;
    }

    // ---- decrypt ----

    internal static int RunDecrypt(Options o, SopIo io)
    {
        string? sessionOut = o.Value("--session-key-out");
        IReadOnlyList<string> sessionIn = o.Values("--with-session-key");
        List<byte[]> pw = Passwords(o, io, "--with-password", false);
        List<byte[]> keyPw = Passwords(o, io, "--with-key-password", false);
        string? vout = o.Value("--verifications-out") ?? o.Value("--verify-out");
        IReadOnlyList<string> verifyWith = o.Values("--verify-with");
        DateTimeOffset? before = ParseDate(o.Value("--verify-not-before"), false);
        DateTimeOffset? after = ParseDate(o.Value("--verify-not-after"), true);
        o.RejectUnknown();
        if ((vout is null) != (verifyWith.Count == 0))
        {
            throw new SopException(SopExit.IncompleteVerification, "--verifications-out and --verify-with must be given together");
        }

        if (o.Positionals.Count == 0 && pw.Count == 0 && sessionIn.Count == 0)
        {
            throw new SopException(SopExit.MissingArg, "decrypt needs keys, a password or a session key");
        }

        var withCipher = new List<(SymmetricAlgorithm, byte[])>();
        foreach (string d in sessionIn)
        {
            using Stream s = io.OpenInput(d);
            string text = Encoding.ASCII.GetString(ReadAll(s)).Trim();
            int colon = text.IndexOf(':', StringComparison.Ordinal);
            if (colon < 1 || !byte.TryParse(text.AsSpan(0, colon), NumberStyles.None, CultureInfo.InvariantCulture, out byte alg))
            {
                throw new SopException(SopExit.BadData, "a session key is written ALGORITHM:HEX");
            }

            try
            {
                withCipher.Add(((SymmetricAlgorithm)alg, Convert.FromHexString(text[(colon + 1)..])));
            }
            catch (FormatException)
            {
                throw new SopException(SopExit.BadData, "a session key is written ALGORITHM:HEX");
            }
        }

        List<PgpCertificate> keys = LoadCerts(o, io, o.Positionals, secret: true);
        List<PgpCertificate> verifiers = LoadCerts(o, io, verifyWith, secret: false);
        Stream? keyOut = sessionOut is null ? null : SopIo.OpenOutput(sessionOut);
        Stream? vstream = vout is null ? null : SopIo.OpenOutput(vout);
        var opts = new PgpReadOptions
        {
            Now = Now(),
            SecretKeys = keys,
            Certificates = verifiers,
            KeyPasswords = keyPw,
            MessagePasswords = pw,
            SessionKeysWithCipher = withCipher,
            Require = PgpRequirement.Encrypted,
        };
        try
        {
            // The library releases plaintext only after it authenticates; stdout is written as the library produces it.
            PgpReadResult r;
            using (Stream binary = io.Stdin)
            {
                r = PgpMessageReader.Read(binary, io.Stdout, opts);
            }

            if (keyOut is not null && r.SessionKey is not null)
            {
                keyOut.Write(Encoding.ASCII.GetBytes($"{(byte)(r.SessionKeyCipher ?? SymmetricAlgorithm.Aes256)}:{Convert.ToHexString(r.SessionKey)}\n"));
            }

            WriteVerifications(vstream, r, before, after);
        }
        catch (PgpException e)
        {
            int code = e.Failure switch
            {
                PgpFailure.KeyIsProtected => SopExit.KeyIsProtected,
                PgpFailure.CannotDecrypt or PgpFailure.NoDecryptionKey or PgpFailure.UnauthenticatedEncryption => SopExit.CannotDecrypt,
                PgpFailure.Unsupported => SopExit.UnsupportedAsymmetricAlgo,
                PgpFailure.LimitExceeded or PgpFailure.MalformedMessage => SopExit.BadData,
                _ => SopExit.UnspecifiedFailure,
            };
            throw new SopException(code, e.Message);
        }
        finally
        {
            keyOut?.Dispose();
            vstream?.Dispose();
        }

        return SopExit.Ok;
    }
}
