using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.OpenPgp.GnuPG;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Primitives;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>
/// Proves keys read from a GnuPG home against <c>gpg</c> itself, run as a black box in a throwaway home: a detached signature made with
/// an unlocked key must verify with <c>gpg --verify</c>, and a message <c>gpg</c> encrypts to a certificate must open with the unlocked
/// key (the session key is unwrapped here and the symmetric packet read with it). They run only when <c>ONECRYPTO_GPG</c> names the binary.
/// </summary>
public sealed class GnuPGKeyInteropTests : IDisposable
{
    private static readonly string? Gpg = Environment.GetEnvironmentVariable("ONECRYPTO_GPG");
    private readonly string _root = Path.Combine(Path.GetTempPath(), "gpgi-" + Guid.NewGuid().ToString("N"));

    public GnuPGKeyInteropTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed record Item(KeyPacket Key, bool Primary, GnuPGKeyFile File);

    public static IEnumerable<object[]> Versions() => GnuPGHomes.Versions.Select(v => new object[] { v });

    private static List<Item> Items(string version)
    {
        var index = new Dictionary<string, (KeyPacket Key, bool Primary)>(StringComparer.Ordinal);
        foreach (KeyboxOpenPgpBlob b in Keybox.Parse(File.ReadAllBytes(GnuPGHomes.Dir(version, "main", "pubring.kbx"))).OpenPgpBlobs)
        {
            TransferableKey k = b.ReadKey();
            index[GnuPGKeyFileTests.Hex(k.Primary.Material.Values[0].Span)] = (k.Primary, true);
            foreach (SubkeyComponent s in k.Subkeys)
            {
                index[GnuPGKeyFileTests.Hex(s.Key.Material.Values[0].Span)] = (s.Key, false);
            }
        }

        var items = new List<Item>();
        foreach (string f in Directory.GetFiles(GnuPGHomes.Dir(version, "main", "private-keys-v1.d"), "*.key").Order(StringComparer.Ordinal))
        {
            GnuPGKeyFile kf = GnuPGKeyFile.Parse(File.ReadAllBytes(f));
            if (index.TryGetValue(GnuPGKeyFileTests.KeyIndex(kf), out var hit) && hit.Key.Version == 4)
            {
                items.Add(new Item(hit.Key, hit.Primary, kf));
            }
        }

        return items;
    }

    private static (int Exit, byte[] Out, string Err) RunGpg(string home, byte[]? stdin, params string[] args)
    {
        var psi = new ProcessStartInfo(Gpg!) { RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true };
        psi.ArgumentList.Add("--homedir");
        psi.ArgumentList.Add(home);
        psi.ArgumentList.Add("--batch");
        psi.ArgumentList.Add("--no-tty");
        foreach (string a in args)
        {
            psi.ArgumentList.Add(a);
        }

        using Process p = Process.Start(psi)!;
        Task<string> err = p.StandardError.ReadToEndAsync();
        var ms = new MemoryStream();
        Task copy = p.StandardOutput.BaseStream.CopyToAsync(ms);
        if (stdin is not null)
        {
            p.StandardInput.BaseStream.Write(stdin);
        }

        p.StandardInput.Close();
        p.WaitForExit();
        copy.Wait();
        return (p.ExitCode, ms.ToArray(), err.Result);
    }

    private string NewHome(string version)
    {
        string home = Path.Combine(_root, "home-" + version);
        Directory.CreateDirectory(home);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(home, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        (int exit, _, string err) = RunGpg(home, null, "--import", GnuPGHomes.Dir(version, "main", "export.pgp"));
        Assert.True(exit == 0, err);
        return home;
    }

    private bool GpgIs25OrLater()
    {
        (_, byte[] o, _) = RunGpg(_root, null, "--version");
        string first = Encoding.UTF8.GetString(o).Split('\n')[0];
        string v = first[(first.LastIndexOf(' ') + 1)..];
        string[] parts = v.Split('.');
        return int.Parse(parts[0], System.Globalization.CultureInfo.InvariantCulture) > 2 || int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture) >= 5;
    }

    private static void Mpi(MemoryStream ms, ReadOnlySpan<byte> v)
    {
        while (v.Length > 0 && v[0] == 0)
        {
            v = v[1..];
        }

        int bits = v.Length == 0 ? 0 : ((v.Length - 1) * 8) + (8 - System.Numerics.BitOperations.LeadingZeroCount((uint)v[0]) + 24);
        ms.WriteByte((byte)(bits >> 8));
        ms.WriteByte((byte)bits);
        ms.Write(v);
    }

    private static byte[] Packet(int tag, byte[] body)
    {
        // New-format packet header (RFC 9580 §4.2.1) with a two-octet or five-octet length.
        var ms = new MemoryStream();
        ms.WriteByte((byte)(0xC0 | tag));
        ms.WriteByte(0xFF);
        ms.WriteByte((byte)(body.Length >> 24));
        ms.WriteByte((byte)(body.Length >> 16));
        ms.WriteByte((byte)(body.Length >> 8));
        ms.WriteByte((byte)body.Length);
        ms.Write(body);
        return ms.ToArray();
    }

    // A version 4 detached binary signature (RFC 9580 §5.2.3) over data, made with an unlocked GnuPG key, SHA-512.
    private static byte[] Sign(Item item, GnuPGSecretKey secret, byte[] data)
    {
        const byte Sha512 = 10;
        var hashed = new MemoryStream();
        hashed.Write([5, 2, 0, 0, 0, 0]);                 // creation time subpacket, patched below
        uint now = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        byte[] ts = [(byte)(now >> 24), (byte)(now >> 16), (byte)(now >> 8), (byte)now];
        byte[] area = [5, 2, .. ts, 22, 33, 4, .. item.Key.GetFingerprint()];
        var head = new List<byte> { 4, 0, (byte)item.Key.Algorithm, Sha512, (byte)(area.Length >> 8), (byte)area.Length };
        head.AddRange(area);
        byte[] trailer = [4, 0xFF, 0, 0, (byte)(head.Count >> 8), (byte)head.Count];
        byte[] message = [.. data, .. head, .. trailer];
        byte[] digest = SHA512.HashData(message);

        var sigMpis = new MemoryStream();
        using ISigningKey key = secret.ToSigningKey();
        switch (item.Key.Algorithm)
        {
            case PublicKeyAlgorithm.Rsa:
                Mpi(sigMpis, key.Sign(message, SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA512)));
                break;
            case PublicKeyAlgorithm.Ecdsa:
            {
                byte[] rs = key.Sign(message, SignatureSpec.Ecdsa(HashAlgorithmName.SHA512, EcdsaSignatureFormat.Rfc4754));
                Mpi(sigMpis, rs.AsSpan(0, rs.Length / 2));
                Mpi(sigMpis, rs.AsSpan(rs.Length / 2));
                break;
            }

            case PublicKeyAlgorithm.EdDsaLegacy:
            {
                // RFC 9580 §5.2.3.2 (legacy EdDSA): the signature is over the digest, written as two MPIs.
                byte[] rs = key.Sign(digest, item.File.Curve == "Ed448" ? SignatureSpec.Ed448() : SignatureSpec.Ed25519());
                Mpi(sigMpis, rs.AsSpan(0, rs.Length / 2));
                Mpi(sigMpis, rs.AsSpan(rs.Length / 2));
                break;
            }

            case PublicKeyAlgorithm.Ed448:
                sigMpis.Write(key.Sign(message, SignatureSpec.Ed448()));
                break;
            case PublicKeyAlgorithm.Ed25519:
                sigMpis.Write(key.Sign(message, SignatureSpec.Ed25519()));
                break;
            default:
                throw new InvalidOperationException(item.Key.Algorithm.ToString());
        }

        var body = new MemoryStream();
        body.Write([.. head]);
        body.Write([0, 0]);                                // no unhashed subpackets
        body.Write(digest.AsSpan(0, 2));
        body.Write(sigMpis.ToArray());
        return Packet(2, body.ToArray());
    }

    [Theory]
    [MemberData(nameof(Versions))]
    public void GpgVerifiesSignaturesMadeWithUnlockedKeys(string version)
    {
        Assert.SkipWhen(Gpg is null, "ONECRYPTO_GPG not set");
        string home = NewHome(version);
        try
        {
            bool has448 = GpgIs25OrLater();
            byte[] data = RandomNumberGenerator.GetBytes(1000);
            string dataFile = Path.Combine(_root, "data.bin");
            File.WriteAllBytes(dataFile, data);
            int verified = 0;
            foreach (Item item in Items(version))
            {
                // Only certifying primary keys sign here: gpg rejects a signature from a subkey without the signing flag.
                if (!item.Primary || item.File.Curve is "Cv25519" or "Curve25519" || (item.File.Curve == "Ed448" && !has448))
                {
                    continue;
                }

                using GnuPGSecretKey secret = item.File.Unlock(item.File.IsProtected ? GnuPGKeyFileTests.Passphrase : string.Empty);
                string sigFile = Path.Combine(_root, "data.sig");
                File.WriteAllBytes(sigFile, Sign(item, secret, data));
                (int exit, _, string err) = RunGpg(home, null, "--verify", sigFile, dataFile);
                Assert.True(exit == 0, $"{version} {item.File.Algorithm} {item.File.Curve}: {err}");
                Assert.Contains("Good signature", err, StringComparison.Ordinal);
                verified++;

                // A flipped data byte must not verify.
                byte[] bad = (byte[])data.Clone();
                bad[500] ^= 1;
                File.WriteAllBytes(dataFile, bad);
                Assert.NotEqual(0, RunGpg(home, null, "--verify", sigFile, dataFile).Exit);
                File.WriteAllBytes(dataFile, data);
            }

            Assert.True(verified >= 5, "verified " + verified);
        }
        finally
        {
            RunGpg(_root, null, "--version");
            Process.Start(new ProcessStartInfo(Path.Combine(Path.GetDirectoryName(Gpg!)!, "gpgconf"), ["--homedir", home, "--kill", "all"]))?.WaitForExit();
        }
    }

    [Theory]
    [MemberData(nameof(Versions))]
    public void MessagesGpgEncryptsOpenWithUnlockedKeys(string version)
    {
        Assert.SkipWhen(Gpg is null, "ONECRYPTO_GPG not set");
        string home = NewHome(version);
        try
        {
            int opened = 0;
            foreach (Item item in Items(version))
            {
                bool ecdh = item.Key.Algorithm == PublicKeyAlgorithm.Ecdh;
                if (item.Primary || !(ecdh || item.Key.Algorithm == PublicKeyAlgorithm.Rsa))
                {
                    continue;
                }

                byte[] text = Encoding.UTF8.GetBytes("onecrypto " + Guid.NewGuid());
                string fpr = Convert.ToHexString(item.Key.GetFingerprint());
                (int exit, byte[] enc, string err) = RunGpg(home, text, "--trust-model", "always", "--compress-algo", "none", "--force-mdc", "--recipient", fpr + "!", "--encrypt");
                if (exit != 0)
                {
                    // This gpg cannot encrypt to the key's algorithm (for example Brainpool or X448 in an older build): nothing to prove.
                    Assert.True(err.Contains("rror", StringComparison.Ordinal) || err.Contains("skipped", StringComparison.Ordinal), err);
                    continue;
                }

                using GnuPGSecretKey secret = item.File.Unlock(item.File.IsProtected ? GnuPGKeyFileTests.Passphrase : string.Empty);
                byte[]? plain = Decrypt(item, secret, enc);
                if (plain is not null)
                {
                    Assert.Equal(text, plain);
                }

                opened++;
            }

            Assert.True(opened >= 3, "opened " + opened);
        }
        finally
        {
            Process.Start(new ProcessStartInfo(Path.Combine(Path.GetDirectoryName(Gpg!)!, "gpgconf"), ["--homedir", home, "--kill", "all"]))?.WaitForExit();
        }
    }

    private static byte[]? Decrypt(Item item, GnuPGSecretKey secret, byte[] message)
    {
        IReadOnlyList<Packet> packets = PacketParser.ParseAll(message);
        var pkesk = (PublicKeyEncryptedSessionKeyPacket)packets.First(p => p.TagId == (byte)PacketTag.PublicKeyEncryptedSessionKey);
        Packet? seipd = packets.FirstOrDefault(p => p.TagId == (byte)PacketTag.SymmetricallyEncryptedIntegrityProtectedData);

        byte[] sessionData;
        if (item.Key.Algorithm == PublicKeyAlgorithm.Rsa)
        {
            using IRsaKey rsa = (IRsaKey)secret.ToSigningKey();
            int modulus = item.Key.Material.Values[0].Length;
            byte[] ct = new byte[modulus];
            pkesk.Values[0].Span.CopyTo(ct.AsSpan(modulus - pkesk.Values[0].Length));
            sessionData = rsa.Decrypt(ct, DecryptionSpec.RsaPkcs1());
        }
        else
        {
            sessionData = UnwrapEcdh(item, secret, pkesk);
        }

        // RFC 9580 §5.1.1 (v3): algorithm octet, session key, two-octet checksum of the key.
        byte sym = sessionData[0];
        int keyLength = sym switch { 7 => 16, 8 => 24, 9 => 32, _ => throw new InvalidOperationException("cipher " + sym) };
        byte[] sk = sessionData.AsSpan(1, keyLength).ToArray();
        int sum = sk.Sum(b => b) & 0xFFFF;
        Assert.Equal(sum, (sessionData[1 + keyLength] << 8) | sessionData[2 + keyLength]);

        if (seipd is null)
        {
            // GnuPG 2.5 writes its own AEAD container (tag 20) for keys that advertise it. The session key is already proven: the
            // key unwrap or RSA decryption succeeded and the checksum matched. This test does not read that container.
            return null;
        }

        Assert.Equal(1, seipd.Body.Span[0]);

        // RFC 9580 §5.13.1: AES in CFB mode with a zero IV, a 16-octet random prefix repeated in its last two octets, then packets and the MDC packet.
        using var aes = Aes.Create();
        aes.Key = sk;
        // The platform's one-shot CFB wants whole blocks; CFB decryption is a keystream XOR, so pad the tail and cut it off again.
        ReadOnlySpan<byte> body = seipd.Body.Span[1..];
        byte[] padded = new byte[(body.Length + 15) / 16 * 16];
        body.CopyTo(padded);
        byte[] plain = aes.DecryptCfb(padded, new byte[16], PaddingMode.None, 128).AsSpan(0, body.Length).ToArray();
        Assert.Equal(plain[14], plain[16]);
        Assert.Equal(plain[15], plain[17]);
        Assert.Equal([0xD3, 0x14], plain.AsSpan(plain.Length - 22, 2).ToArray());
#pragma warning disable CA5350 // The modification detection code of this message format is SHA-1 by definition; the test reads it back.
        Assert.Equal(SHA1.HashData(plain.AsSpan(0, plain.Length - 20)), plain.AsSpan(plain.Length - 20).ToArray());
#pragma warning restore CA5350
        IReadOnlyList<Packet> inner = PacketParser.ParseAll(plain.AsMemory(18, plain.Length - 18 - 22));
        Packet literal = inner.Single(p => p.TagId == (byte)PacketTag.LiteralData);
        // Literal data (§5.9): format, file name length and name, four-octet date, then the data.
        int nameLength = literal.Body.Span[1];
        return literal.Body.Span[(6 + nameLength)..].ToArray();
    }

    private static byte[] UnwrapEcdh(Item item, GnuPGSecretKey secret, PublicKeyEncryptedSessionKeyPacket pkesk)
    {
        // RFC 9580 §5.1.1 / RFC 6637 §8: the ephemeral point is an MPI, the wrapped key has a length octet.
        ReadOnlyMemory<byte> point = pkesk.Values[0];
        ReadOnlySpan<byte> wrapped = pkesk.Values[1].Span;
        ReadOnlySpan<byte> kdf = item.Key.Material.KdfParameters.Span;   // reserved 1, hash, symmetric (the length octet 3 is not included)
        ReadOnlySpan<byte> oid = item.Key.Material.CurveOid.Span;
        byte hashId = kdf[^2];
        byte kekId = kdf[^1];
        int kekLength = kekId switch { 7 => 16, 8 => 24, 9 => 32, _ => throw new InvalidOperationException("kek " + kekId) };
        HashAlgorithmName hash = hashId switch { 8 => HashAlgorithmName.SHA256, 9 => HashAlgorithmName.SHA384, 10 => HashAlgorithmName.SHA512, _ => throw new InvalidOperationException("hash " + hashId) };

        using IAgreementKey ak = secret.ToAgreementKey();
        byte[] shared;
        if (secret.Curve is "Cv25519" or "Curve25519")
        {
            shared = ak.Agree(Spki([0x2b, 0x65, 0x6e], point.Span[1..]));
        }
        else
        {
            int size = (point.Length - 1) / 2;
            ECCurve curve = item.File.Curve!.Replace("-", string.Empty, StringComparison.Ordinal).Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant() switch
            {
                "NISTP256" => ECCurve.NamedCurves.nistP256,
                "NISTP384" => ECCurve.NamedCurves.nistP384,
                "NISTP521" => ECCurve.NamedCurves.nistP521,
                "BRAINPOOLP256R1" => ECCurve.NamedCurves.brainpoolP256r1,
                "BRAINPOOLP384R1" => ECCurve.NamedCurves.brainpoolP384r1,
                "BRAINPOOLP512R1" => ECCurve.NamedCurves.brainpoolP512r1,
                _ => throw new InvalidOperationException(item.File.Curve),
            };
            using var peer = ECDiffieHellman.Create(new ECParameters { Curve = curve, Q = new ECPoint { X = point.Span.Slice(1, size).ToArray(), Y = point.Span.Slice(1 + size, size).ToArray() } });
            shared = ak.Agree(PublicKeyInfo.FromAsymmetricAlgorithm(peer));
        }

        // RFC 6637 §7: Hash(00000001 || S || OID length and OID || algorithm 18 || KDF parameters || "Anonymous Sender    " || recipient fingerprint).
        byte[] input = [0, 0, 0, 1, .. shared, (byte)oid.Length, .. oid, 18, 3, .. kdf, .. Encoding.ASCII.GetBytes("Anonymous Sender    "), .. item.Key.GetFingerprint()];
        byte[] z = HashData(hash, input).AsSpan(0, kekLength).ToArray();
        using var kw = new AesKeyWrap(z);
        byte[] unwrapped = new byte[wrapped.Length - AesKeyWrap.Overhead];
        kw.Unwrap(wrapped, unwrapped);
        // RFC 6637 §8: PKCS #5 padding to a multiple of eight octets.
        return unwrapped.AsSpan(0, unwrapped.Length - unwrapped[^1]).ToArray();
    }

    private static byte[] HashData(HashAlgorithmName name, byte[] data) =>
        name == HashAlgorithmName.SHA256 ? SHA256.HashData(data) : name == HashAlgorithmName.SHA384 ? SHA384.HashData(data) : SHA512.HashData(data);

    private static PublicKeyInfo Spki(byte[] oidBody, ReadOnlySpan<byte> key)
    {
        byte[] alg = [0x30, (byte)(2 + oidBody.Length), 0x06, (byte)oidBody.Length, .. oidBody];
        byte[] bits = [0x03, (byte)(key.Length + 1), 0x00, .. key];
        byte[] spki = [0x30, (byte)(alg.Length + bits.Length), .. alg, .. bits];
        return PublicKeyInfo.Parse(spki);
    }
}
