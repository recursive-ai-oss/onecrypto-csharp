#pragma warning disable CA5350 // The key-file protection is defined over SHA-1 (S2K and the integrity hash); reading existing keys needs it.
using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto.Internal;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Primitives;

namespace RecursiveAI.OneCrypto.OpenPgp.GnuPG;

/// <summary>
/// The decrypted secret parameters of a key file, held in a pinned buffer that is zeroed on dispose. Turn it into a key with
/// <see cref="ToSigningKey"/>, <see cref="ToDecryptionKey"/> or <see cref="ToAgreementKey"/>; each returned key owns its own copy of the
/// material and can outlive this object. A garbage-collected runtime cannot promise that no other copy of a secret was ever made.
/// </summary>
public sealed class GnuPGSecretKey : IDisposable
{
    private readonly Dictionary<string, (int Offset, int Length)> _slots = new(StringComparer.Ordinal);
    private readonly Dictionary<string, byte[]> _public = new(StringComparer.Ordinal);
    private PinnedSecret? _secret;

    private GnuPGSecretKey(string algorithm, string? curve)
    {
        Algorithm = algorithm;
        Curve = curve;
    }

    /// <summary>The algorithm name as the key expression gives it, lower case.</summary>
    public string Algorithm { get; }

    /// <summary>The curve name of an <c>ecc</c> key as written, or null.</summary>
    public string? Curve { get; }

    internal static GnuPGSecretKey FromClear(GnuPGKeyFile file, SexpList alg, GnuPGLimits limits)
    {
        var key = new GnuPGSecretKey(file.Algorithm, file.Curve);
        try
        {
            string[] names = SecretNames(file.Algorithm);
            key.CollectPublic(alg, names);
            var items = new List<(string, byte[])>();
            foreach (string n in names)
            {
                if (alg.Value(n) is { } v)
                {
                    items.Add((n, v));
                }
            }

            key.Store(items);
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    internal static GnuPGSecretKey FromProtected(GnuPGKeyFile file, SexpList alg, byte[] associatedData, ReadOnlySpan<char> passphrase, GnuPGLimits limits)
    {
        (byte[] salt, long count, byte[] ivOrNonce, byte[] encrypted) = file.ProtectionParameters();
        if (count > limits.MaxS2kCount)
        {
            throw new KdfLimitExceededException("S2K", "iteration count (bytes hashed)", count, limits.MaxS2kCount);
        }

        // The protection key is the first 128 bits of the iterated and salted S2K (RFC 9580 §3.7.1.3) over SHA-1 of the passphrase.
        using var pass = new PinnedSecret(Encoding.UTF8.GetByteCount(passphrase));
        Encoding.UTF8.GetBytes(passphrase, pass.Span);
        using var aesKey = new PinnedSecret(16);
        IteratedSalted.Sha1(salt, pass.ReadOnlySpan, count, aesKey.Span);

        var key = new GnuPGSecretKey(file.Algorithm, file.Curve);
        PinnedSecret? plain = null;
        try
        {
            string[] names = SecretNames(file.Algorithm);
            key.CollectPublic(alg, names);
            if (file.Protection == GnuPGKeyProtection.OcbAes)
            {
                // AES-128-OCB, 96-bit nonce, 128-bit tag at the end of the ciphertext; the public key expression is the associated data.
                if (ivOrNonce.Length != 12 || encrypted.Length < 16)
                {
                    throw new GnuPGFormatException(GnuPGError.BadSyntax, 0, "OCB nonce or ciphertext length");
                }

                plain = new PinnedSecret(encrypted.Length - 16);
                using var ocb = new AesOcb(aesKey.ReadOnlySpan, 16);
                if (!ocb.TryDecrypt(ivOrNonce, encrypted.AsSpan(0, encrypted.Length - 16), encrypted.AsSpan(encrypted.Length - 16), plain.Span, associatedData))
                {
                    throw new GnuPGWrongPassphraseException();
                }
            }
            else
            {
                if (ivOrNonce.Length != 16 || encrypted.Length == 0 || encrypted.Length % 16 != 0)
                {
                    throw new GnuPGFormatException(GnuPGError.BadSyntax, 0, "CBC IV or ciphertext length");
                }

                plain = new PinnedSecret(encrypted.Length);
                Platform.RequireAes("AES-CBC");
                using Aes aes = Platform.CreateAes();
                aes.SetKey(aesKey.ReadOnlySpan);
                aes.DecryptCbc(encrypted, ivOrNonce, plain.Span, PaddingMode.None);
            }

            List<(string Name, int Offset, int Length)> found = ParseSecretList(plain.ReadOnlySpan, file.Protection == GnuPGKeyProtection.Sha1AesCbc, out ReadOnlySpan<byte> sha1, names);
            if (file.Protection == GnuPGKeyProtection.Sha1AesCbc)
            {
                // The hash covers the whole key expression with the secret parameters inserted after the public ones, protected-at last.
                using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
                AppendAlgorithmStart(h, alg);
                foreach (SexpNode n in alg.Items.Skip(1))
                {
                    if (n is SexpList l && l.Name is "protected" or "protected-at")
                    {
                        continue;
                    }

                    h.AppendData(SexpWriter.Canonical(n));
                }

                foreach ((string name, int off, int len) in found)
                {
                    AppendItem(h, name, plain.ReadOnlySpan.Slice(off, len));
                }

                if (alg.Find("protected-at") is { } at)
                {
                    h.AppendData(SexpWriter.Canonical(at));
                }

                h.AppendData(")"u8);
                Span<byte> digest = stackalloc byte[20]; // fixed small buffer
                h.GetHashAndReset(digest);
                if (!CryptographicOperations.FixedTimeEquals(digest, sha1))
                {
                    throw new GnuPGWrongPassphraseException();
                }
            }

            var items = new List<(string, byte[])>();
            foreach ((string name, int off, int len) in found)
            {
                items.Add((name, plain.ReadOnlySpan.Slice(off, len).ToArray()));
            }

            try
            {
                key.Store(items);
            }
            finally
            {
                foreach ((string _, byte[] v) in items)
                {
                    CryptographicOperations.ZeroMemory(v);
                }
            }

            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
        finally
        {
            plain?.Dispose();
        }
    }

    private static void AppendAlgorithmStart(IncrementalHash h, SexpList alg)
    {
        string name = ((SexpAtom)alg.Items[0]).Text;
        h.AppendData("("u8);
        h.AppendData(Encoding.ASCII.GetBytes(name.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" + name));
    }

    private static void AppendItem(IncrementalHash h, string name, ReadOnlySpan<byte> value)
    {
        h.AppendData("("u8);
        h.AppendData(Encoding.ASCII.GetBytes(name.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" + name));
        h.AppendData(Encoding.ASCII.GetBytes(value.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":"));
        h.AppendData(value);
        h.AppendData(")"u8);
    }

    // The decrypted plaintext is canonical: ( ( (1:d N:…)(1:p N:…)… ) [ (4:hash 4:sha1 20:…) ] ) followed by random padding. It is scanned in
    // place, with every length checked, so no secret leaves the pinned buffer.
    private static List<(string Name, int Offset, int Length)> ParseSecretList(ReadOnlySpan<byte> p, bool withHash, out ReadOnlySpan<byte> sha1, string[] allowed)
    {
        sha1 = default;
        var found = new List<(string, int, int)>();
        int pos = 0;
        Expect(p, ref pos, '(');
        Expect(p, ref pos, '(');
        while (pos < p.Length && p[pos] == '(')
        {
            pos++;
            string name = Atom(p, ref pos, out _, out _);
            _ = Atom(p, ref pos, out int valueOffset, out int valueLength);
            Expect(p, ref pos, ')');
            if (Array.IndexOf(allowed, name) < 0 || found.Exists(f => f.Item1 == name))
            {
                throw new GnuPGFormatException(GnuPGError.BadSyntax, pos, "secret parameter name");
            }

            found.Add((name, valueOffset, valueLength));
        }

        Expect(p, ref pos, ')');
        if (withHash)
        {
            Expect(p, ref pos, '(');
            if (Atom(p, ref pos, out _, out _) != "hash" || Atom(p, ref pos, out _, out _) != "sha1")
            {
                throw new GnuPGFormatException(GnuPGError.BadSyntax, pos, "hash element");
            }

            _ = Atom(p, ref pos, out int hashOffset, out int hashLength);
            if (hashLength != 20)
            {
                throw new GnuPGFormatException(GnuPGError.BadSyntax, pos, "hash length");
            }

            Expect(p, ref pos, ')');
            sha1 = p.Slice(hashOffset, 20);
        }

        Expect(p, ref pos, ')');
        if (found.Count == 0)
        {
            throw new GnuPGFormatException(GnuPGError.BadSyntax, 0, "no secret parameters");
        }

        return found;
    }

    private static void Expect(ReadOnlySpan<byte> p, ref int pos, char c)
    {
        if (pos >= p.Length || p[pos] != c)
        {
            throw new GnuPGFormatException(GnuPGError.BadSyntax, pos, "secret parameter list");
        }

        pos++;
    }

    // One verbatim atom "N:bytes". Returns it as text when short (for names); offset and length locate the octets.
    private static string Atom(ReadOnlySpan<byte> p, ref int pos, out int offset, out int length)
    {
        long n = 0;
        int digits = 0;
        while (pos < p.Length && p[pos] is >= (byte)'0' and <= (byte)'9')
        {
            n = (n * 10) + (p[pos] - '0');
            if (n > p.Length)
            {
                throw new GnuPGFormatException(GnuPGError.OutOfBounds, pos, "atom length");
            }

            pos++;
            digits++;
        }

        if (digits == 0 || pos >= p.Length || p[pos] != ':' || n > p.Length - pos - 1)
        {
            throw new GnuPGFormatException(GnuPGError.BadSyntax, pos, "secret parameter atom");
        }

        pos++;
        offset = pos;
        length = (int)n;
        pos += length;
        return length <= 16 ? Encoding.Latin1.GetString(p.Slice(offset, length)) : string.Empty;
    }

    private static string[] SecretNames(string algorithm) => algorithm switch
    {
        "rsa" => ["d", "p", "q", "u"],
        "ecc" => ["d"],
        "dsa" or "elg" => ["x"],
        _ => throw new NotSupportedException($"Secret keys of algorithm '{algorithm}' are not supported."),
    };

    private void CollectPublic(SexpList alg, string[] secretNames)
    {
        foreach (SexpNode n in alg.Items)
        {
            if (n is SexpList l && l.Name is { } name && Array.IndexOf(secretNames, name) < 0 && name is not ("protected" or "protected-at" or "shadowed")
                && l.Items.Count >= 2 && l.Items[1] is SexpAtom v)
            {
                _public[name] = v.Value;
            }
        }
    }

    private void Store(List<(string Name, byte[] Value)> items)
    {
        int total = 0;
        foreach ((string _, byte[] v) in items)
        {
            total += v.Length;
        }

        _secret = new PinnedSecret(total);
        int off = 0;
        foreach ((string name, byte[] v) in items)
        {
            v.CopyTo(_secret.Span[off..]);
            _slots[name] = (off, v.Length);
            off += v.Length;
        }
    }

    private ReadOnlySpan<byte> Secret(string name)
    {
        ObjectDisposedException.ThrowIf(_secret is null, this);
        if (!_slots.TryGetValue(name, out (int Offset, int Length) s))
        {
            throw new GnuPGFormatException(GnuPGError.BadSyntax, 0, $"missing secret parameter '{name}'");
        }

        return _secret.ReadOnlySpan.Slice(s.Offset, s.Length);
    }

    private byte[] Pub(string name) => _public.TryGetValue(name, out byte[]? v) ? v : throw new GnuPGFormatException(GnuPGError.BadSyntax, 0, $"missing public parameter '{name}'");

    /// <summary>The octets of a public parameter as stored (including the leading zero of an unsigned integer), or empty.</summary>
    /// <param name="name">The parameter name.</param>
    public ReadOnlyMemory<byte> GetPublicParameter(string name) => _public.TryGetValue(name, out byte[]? v) ? v : [];

    /// <summary>
    /// A signing key: RSA (PKCS #1 or PSS), ECDSA over the curves the platform offers, Ed25519 or Ed448. The returned key owns its key material.
    /// </summary>
    /// <exception cref="NotSupportedException">The algorithm or curve is not one that signs, or the platform lacks it.</exception>
    /// <exception cref="GnuPGFormatException">The key material does not form a valid key, or the public point does not match the secret.</exception>
    public ISigningKey ToSigningKey()
    {
        switch (Algorithm)
        {
            case "rsa":
                return CreateRsa();
            case "ecc":
                switch (CurveKind())
                {
                    case Kind.Ed25519:
                        return PrivateKey.FromEd25519(CreateEd25519(), ownsKey: true);
                    case Kind.Ed448:
                        return PrivateKey.FromEd448(CreateEd448(), ownsKey: true);
                    case Kind.Nist:
                        return PrivateKey.FromECDsa(CreateEcdsa(), ownsKey: true);
                }

                break;
        }

        throw new NotSupportedException($"A {Algorithm} key{(Curve is null ? string.Empty : " on " + Curve)} cannot sign.");
    }

    /// <summary>A decryption key: RSA (PKCS #1 v1.5 or OAEP). Elliptic-curve decryption goes through <see cref="ToAgreementKey"/>.</summary>
    /// <exception cref="NotSupportedException">The key is not an RSA key.</exception>
    public IDecryptionKey ToDecryptionKey() =>
        Algorithm == "rsa" ? CreateRsa() : throw new NotSupportedException($"A {Algorithm} key does not decrypt directly; use ToAgreementKey for elliptic-curve keys.");

    /// <summary>A key-agreement key: ECDH over the platform's curves, X25519 or X448. The returned key owns its key material.</summary>
    /// <exception cref="NotSupportedException">The key is not an elliptic-curve key that agrees, or the platform lacks the curve.</exception>
    public IAgreementKey ToAgreementKey()
    {
        if (Algorithm == "ecc")
        {
            switch (CurveKind())
            {
                case Kind.X25519:
                    return PrivateKey.FromX25519(CreateX25519(), ownsKey: true);
                case Kind.X448:
                    return PrivateKey.FromX448(CreateX448(), ownsKey: true);
                case Kind.Nist:
                    return PrivateKey.FromECDiffieHellman(CreateEcdh(), ownsKey: true);
            }
        }

        throw new NotSupportedException($"A {Algorithm} key{(Curve is null ? string.Empty : " on " + Curve)} cannot agree on a shared secret.");
    }

    /// <summary>Zeroes the decrypted parameters.</summary>
    public void Dispose()
    {
        _secret?.Dispose();
        _secret = null;
        _slots.Clear();
    }

    private enum Kind
    {
        Nist,
        Ed25519,
        X25519,
        Ed448,
        X448,
    }

    private Kind CurveKind() => (Curve ?? string.Empty).ToUpperInvariant() switch
    {
        "ED25519" => Kind.Ed25519,
        "CURVE25519" or "CV25519" => Kind.X25519,
        "ED448" => Kind.Ed448,
        "X448" or "CURVE448" or "CV448" => Kind.X448,
        _ => Kind.Nist,
    };

    private IRsaKey CreateRsa()
    {
        byte[] n = StripZeros(Pub("n"));
        byte[] e = StripZeros(Pub("e"));
        ReadOnlySpan<byte> d = Secret("d");
        ReadOnlySpan<byte> p = Secret("p");
        ReadOnlySpan<byte> q = Secret("q");
        ReadOnlySpan<byte> u = Secret("u");
        int half = (n.Length + 1) / 2;

        // GnuPG's u is p^-1 mod q; the platform's InverseQ is Q^-1 mod P. So the platform's P is GnuPG's q and its Q is GnuPG's p.
        byte[] pm1 = TrimTo(q).ToArray();
        byte[] qm1 = TrimTo(p).ToArray();
        if (pm1.Length == 0 || qm1.Length == 0 || (pm1[^1] & 1) == 0 || (qm1[^1] & 1) == 0)
        {
            throw new GnuPGFormatException(GnuPGError.Invalid, 0, "RSA primes must be odd");
        }

        pm1[^1] &= 0xFE; // the primes are odd, so prime - 1 only clears the lowest bit
        qm1[^1] &= 0xFE;
        byte[] dp = new byte[pm1.Length];
        byte[] dq = new byte[qm1.Length];
        var prm = new RSAParameters
        {
            Modulus = n,
            Exponent = e,
            D = SecretMod.Fixed(d, n.Length),
            P = SecretMod.Fixed(q, half),
            Q = SecretMod.Fixed(p, half),
            InverseQ = SecretMod.Fixed(u, half),
        };
        try
        {
            SecretMod.Reduce(d, pm1, dp);
            SecretMod.Reduce(d, qm1, dq);
            prm.DP = SecretMod.Fixed(dp, half);
            prm.DQ = SecretMod.Fixed(dq, half);
            RSA rsa = Platform.CreateRsa("GnuPG RSA key");
            try
            {
                rsa.ImportParameters(prm);
            }
            catch (CryptographicException ex)
            {
                rsa.Dispose();
                throw new GnuPGFormatException("The RSA parameters are inconsistent.", ex);
            }

            return PrivateKey.FromRsa(rsa, ownsKey: true);
        }
        finally
        {
            foreach (byte[]? x in new[] { pm1, qm1, dp, dq, prm.D, prm.P, prm.Q, prm.InverseQ, prm.DP, prm.DQ })
            {
                if (x is not null)
                {
                    CryptographicOperations.ZeroMemory(x);
                }
            }
        }
    }

    private static ReadOnlySpan<byte> TrimTo(ReadOnlySpan<byte> s)
    {
        while (s.Length > 0 && s[0] == 0)
        {
            s = s[1..];
        }

        return s;
    }

    private static byte[] StripZeros(byte[] v) => TrimTo(v).ToArray();

    private Ed25519PrivateKey CreateEd25519()
    {
        ReadOnlySpan<byte> d = Secret("d");
        byte[] seed = new byte[32];
        try
        {
            Fixed(d, seed);
            Ed25519PrivateKey k = Ed25519PrivateKey.FromSeed(seed);
            CheckPoint(k.PublicKey.ToArray(), Pub("q"), 32, prefixed: true, k);
            return k;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    private Ed448PrivateKey CreateEd448()
    {
        ReadOnlySpan<byte> d = Secret("d");
        byte[] seed = new byte[57];
        try
        {
            Fixed(d, seed);
            Ed448PrivateKey k = Ed448PrivateKey.FromSeed(seed);
            CheckPoint(k.PublicKey.ToArray(), Pub("q"), 57, prefixed: false, k);
            return k;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    private X25519PrivateKey CreateX25519()
    {
        ReadOnlySpan<byte> d = Secret("d");
        byte[] scalar = new byte[32];
        try
        {
            // GnuPG keeps the Curve25519 scalar as the OpenPGP integer: big-endian, where RFC 7748 uses little-endian.
            Fixed(d, scalar);
            Array.Reverse(scalar);
            X25519PrivateKey k = X25519PrivateKey.FromBytes(scalar);
            CheckPoint(k.PublicKey.ToArray(), Pub("q"), 32, prefixed: true, k);
            return k;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(scalar);
        }
    }

    private X448PrivateKey CreateX448()
    {
        ReadOnlySpan<byte> d = Secret("d");
        byte[] scalar = new byte[56];
        try
        {
            Fixed(d, scalar);
            Array.Reverse(scalar);
            X448PrivateKey k = X448PrivateKey.FromBytes(scalar);
            CheckPoint(k.PublicKey.ToArray(), Pub("q"), 56, prefixed: true, k);
            return k;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(scalar);
        }
    }

    // The stored point is the public key, with a 0x40 prefix for the Montgomery and Edwards-25519 forms GnuPG writes.
    private static void CheckPoint(byte[] derived, byte[] stored, int size, bool prefixed, IDisposable owner)
    {
        ReadOnlySpan<byte> q = stored;
        if (prefixed && q.Length == size + 1 && q[0] == 0x40)
        {
            q = q[1..];
        }

        if (!q.SequenceEqual(derived)) // public data
        {
            owner.Dispose();
            throw new GnuPGFormatException(GnuPGError.Invalid, 0, "the public point does not match the secret scalar");
        }
    }

    private static void Fixed(ReadOnlySpan<byte> value, Span<byte> destination)
    {
        value = TrimTo(value);
        if (value.Length > destination.Length)
        {
            throw new GnuPGFormatException(GnuPGError.Invalid, 0, "secret scalar too long");
        }

        destination.Clear();
        value.CopyTo(destination[(destination.Length - value.Length)..]);
    }

    private ECParameters EcParameters()
    {
        (ECCurve curve, int size) = Curve!.ToUpperInvariant().Replace(" ", string.Empty, StringComparison.Ordinal).Replace("-", string.Empty, StringComparison.Ordinal) switch
        {
            "NISTP256" or "SECP256R1" or "PRIME256V1" => (ECCurve.NamedCurves.nistP256, 32),
            "NISTP384" or "SECP384R1" => (ECCurve.NamedCurves.nistP384, 48),
            "NISTP521" or "SECP521R1" => (ECCurve.NamedCurves.nistP521, 66),
            "BRAINPOOLP256R1" => (ECCurve.NamedCurves.brainpoolP256r1, 32),
            "BRAINPOOLP384R1" => (ECCurve.NamedCurves.brainpoolP384r1, 48),
            "BRAINPOOLP512R1" => (ECCurve.NamedCurves.brainpoolP512r1, 64),
            _ => throw new NotSupportedException($"The curve '{Curve}' is not supported."),
        };
        byte[] q = Pub("q");
        if (q.Length != (2 * size) + 1 || q[0] != 4)
        {
            throw new GnuPGFormatException(GnuPGError.Invalid, 0, "public point is not an uncompressed point of the curve");
        }

        var prm = new ECParameters
        {
            Curve = curve,
            Q = new ECPoint { X = q.AsSpan(1, size).ToArray(), Y = q.AsSpan(1 + size, size).ToArray() },
            D = SecretMod.Fixed(Secret("d"), size),
        };
        return prm;
    }

    private ECDsa CreateEcdsa()
    {
        ECParameters prm = EcParameters();
        try
        {
            return Platform.CreateEcdsa(prm, "GnuPG ECDSA key");
        }
        catch (CryptographicException ex)
        {
            throw new GnuPGFormatException("The elliptic-curve parameters are inconsistent.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prm.D);
        }
    }

    private ECDiffieHellman CreateEcdh()
    {
        ECParameters prm = EcParameters();
        try
        {
            return ECDiffieHellman.Create(prm);
        }
        catch (CryptographicException ex)
        {
            throw new GnuPGFormatException("The elliptic-curve parameters are inconsistent.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prm.D);
        }
    }
}

/// <summary>The iterated and salted S2K of RFC 9580 §3.7.1.3 over SHA-1, as the key-file protection uses it.</summary>
internal static class IteratedSalted
{
    /// <summary>Fills <paramref name="key"/> (at most 20 octets) from the first digest of SHA-1 over the repeated salt and passphrase, <paramref name="count"/> octets in all.</summary>
    public static void Sha1(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> passphrase, long count, Span<byte> key)
    {
        int unit = salt.Length + passphrase.Length;
        using var data = new PinnedSecret(unit);
        salt.CopyTo(data.Span);
        passphrase.CopyTo(data.Span[salt.Length..]);

        // RFC 9580 §3.7.1.3: when the count is smaller than one salt-and-passphrase unit, exactly one unit is hashed.
        long total = Math.Max(count, unit);

        // Hash in large runs made of whole units so a count of hundreds of megabytes costs thousands of calls, not millions.
        int units = Math.Max(1, 8192 / unit);
        using var run = new PinnedSecret(units * unit);
        for (int i = 0; i < units; i++)
        {
            data.ReadOnlySpan.CopyTo(run.Span[(i * unit)..]);
        }

        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        long remaining = total;
        while (remaining >= run.Length)
        {
            h.AppendData(run.ReadOnlySpan);
            remaining -= run.Length;
        }

        if (remaining > 0)
        {
            h.AppendData(run.ReadOnlySpan[..(int)remaining]);
        }

        Span<byte> digest = stackalloc byte[20]; // fixed small buffer
        h.GetHashAndReset(digest);
        digest[..key.Length].CopyTo(key);
        CryptographicOperations.ZeroMemory(digest);
    }
}
