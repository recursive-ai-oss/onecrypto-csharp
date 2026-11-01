using System.Text;
using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using RecursiveAI.OneCrypto.OpenPgp;

namespace OneCrypto.Benchmarks;

// OpenPGP messages against the comparator, on the same version 4 test keys (testdata/openpgp/keys, made by GnuPG), the same data and the
// same work: detached signatures with SHA-512, and password messages with AES-256, SHA-256 iterated-salted S2K and an integrity packet
// (SEIPD v1, which is what the comparator writes). Both sides work from and to memory.

internal static class PgpBenchKeys
{
    // The keys sit in the repository's testdata; the source path is baked in at compile time so the bench can run from any output folder.
    private static string Path(string name, [System.Runtime.CompilerServices.CallerFilePath] string thisFile = "") =>
        System.IO.Path.GetFullPath(System.IO.Path.Combine(System.IO.Path.GetDirectoryName(thisFile)!, "..", "..", "..", "testdata", "openpgp", "keys", name));

    internal static byte[] Bytes(string name) => File.ReadAllBytes(Path(name));

    internal static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    internal static PgpPrivateKey BcPrivate(string name)
    {
        using var s = new MemoryStream(Bytes(name));
        var bundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(s));
        foreach (PgpSecretKeyRing ring in bundle.GetKeyRings())
        {
            foreach (Org.BouncyCastle.Bcpg.OpenPgp.PgpSecretKey k in ring.GetSecretKeys())
            {
                if (k.IsSigningKey)
                {
                    return k.ExtractPrivateKey(Array.Empty<char>());
                }
            }
        }

        throw new InvalidOperationException("no signing key");
    }

    internal static PgpPublicKey BcPublic(string name)
    {
        using var s = new MemoryStream(Bytes(name));
        var bundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(s));
        return bundle.GetKeyRings().First().GetPublicKey();
    }
}

/// <summary>Detached signing with a version 4 key against the comparator.</summary>
[BenchmarkCategory("openpgp")]
public class PgpSignRows : IDisposable
{
    private RecursiveAI.OneCrypto.OpenPgp.PgpSecretKey? _ours;
    private PgpPrivateKey _bcKey = null!;
    private PublicKeyAlgorithmTag _bcAlg;
    private byte[] _data = [];

    /// <summary>The key: rsa3072 or ed25519.</summary>
    [Params("rsa3072", "ed25519")]
    public string Key { get; set; } = "";

    /// <summary>Data size in bytes.</summary>
    [Params(1024)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _data = new byte[Size];
        new Random(1).NextBytes(_data);
        PgpCertificate cert = PgpCertificate.Parse(PgpBenchKeys.Bytes("test-" + Key + ".sec.asc"));
        _ours = RecursiveAI.OneCrypto.OpenPgp.PgpSecretKey.Unlock(cert.Primary);
        _bcKey = PgpBenchKeys.BcPrivate("test-" + Key + ".sec.asc");
        _bcAlg = Key == "rsa3072" ? PublicKeyAlgorithmTag.RsaGeneral : PublicKeyAlgorithmTag.EdDsa_Legacy;
    }

    [Benchmark]
    public int Ours()
    {
        using var output = new MemoryStream();
        PgpMessageWriter.SignDetached(new MemoryStream(_data, writable: false), output, new PgpWriteOptions { Now = PgpBenchKeys.Now, Signers = [_ours!] });
        return (int)output.Length;
    }

    [Benchmark]
    public int BouncyCastle()
    {
        var gen = new PgpSignatureGenerator(_bcAlg, HashAlgorithmTag.Sha512);
        gen.InitSign(PgpSignature.BinaryDocument, _bcKey);
        gen.Update(_data, 0, _data.Length);
        using var output = new MemoryStream();
        gen.Generate().Encode(output);
        return (int)output.Length;
    }

    public void Dispose()
    {
        _ours?.Dispose();
        GC.SuppressFinalize(this);
    }
}

/// <summary>Detached verification with a version 4 key against the comparator.</summary>
[BenchmarkCategory("openpgp")]
public class PgpVerifyRows
{
    private PgpCertificate _cert = null!;
    private PgpPublicKey _bcKey = null!;
    private byte[] _data = [];
    private byte[] _sig = [];

    /// <summary>The key: rsa3072 or ed25519.</summary>
    [Params("rsa3072", "ed25519")]
    public string Key { get; set; } = "";

    /// <summary>Data size in bytes.</summary>
    [Params(1024)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _data = new byte[Size];
        new Random(2).NextBytes(_data);
        PgpCertificate secret = PgpCertificate.Parse(PgpBenchKeys.Bytes("test-" + Key + ".sec.asc"));
        _cert = PgpCertificate.Parse(PgpBenchKeys.Bytes("test-" + Key + ".pub.asc"));
        _bcKey = PgpBenchKeys.BcPublic("test-" + Key + ".pub.asc");
        using RecursiveAI.OneCrypto.OpenPgp.PgpSecretKey signer = RecursiveAI.OneCrypto.OpenPgp.PgpSecretKey.Unlock(secret.Primary);
        using var sig = new MemoryStream();
        PgpMessageWriter.SignDetached(new MemoryStream(_data), sig, new PgpWriteOptions { Now = PgpBenchKeys.Now, Signers = [signer] });
        _sig = sig.ToArray();
    }

    [Benchmark]
    public bool Ours() => PgpMessageReader.VerifyDetached(new MemoryStream(_data, writable: false), new MemoryStream(_sig, writable: false), new PgpReadOptions { Now = PgpBenchKeys.Now, Certificates = [_cert] }).Signatures[0].IsValid;

    [Benchmark]
    public bool BouncyCastle()
    {
        using var s = new MemoryStream(_sig, writable: false);
        var factory = new PgpObjectFactory(s);
        var list = (PgpSignatureList)factory.NextPgpObject();
        PgpSignature sig = list[0];
        sig.InitVerify(_bcKey);
        sig.Update(_data, 0, _data.Length);
        return sig.Verify();
    }
}

/// <summary>Password encryption (SEIPD v1, AES-256) against the comparator.</summary>
[BenchmarkCategory("openpgp")]
public class PgpPasswordEncryptRows
{
    private static readonly byte[] Password = Encoding.UTF8.GetBytes("bench password");
    private byte[] _data = [];

    /// <summary>Message size in bytes.</summary>
    [Params(1024, 64 * 1024 * 1024)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _data = new byte[Size];
        new Random(3).NextBytes(_data);
    }

    [Benchmark]
    public int Ours()
    {
        using var output = new MemoryStream();
        PgpMessageWriter.Write(new MemoryStream(_data, writable: false), output, new PgpWriteOptions { Now = PgpBenchKeys.Now, Passwords = [Password], ForceSeipd1 = true });
        return (int)output.Length;
    }

    [Benchmark]
    public int BouncyCastle()
    {
        using var output = new MemoryStream();
        var enc = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true);
        enc.AddMethod("bench password".ToCharArray(), HashAlgorithmTag.Sha256);
        using (Stream e = enc.Open(output, new byte[1 << 16]))
        {
            var lit = new PgpLiteralDataGenerator();
            using Stream l = lit.Open(e, PgpLiteralData.Binary, "f", _data.Length, DateTime.UtcNow);
            l.Write(_data, 0, _data.Length);
        }

        return (int)output.Length;
    }
}

/// <summary>Password decryption (SEIPD v1, AES-256, integrity check) against the comparator.</summary>
[BenchmarkCategory("openpgp")]
public class PgpPasswordDecryptRows
{
    private static readonly byte[] Password = Encoding.UTF8.GetBytes("bench password");
    private byte[] _message = [];

    /// <summary>Message size in bytes.</summary>
    [Params(1024, 64 * 1024 * 1024)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        byte[] data = new byte[Size];
        new Random(4).NextBytes(data);
        using var output = new MemoryStream();
        PgpMessageWriter.Write(new MemoryStream(data), output, new PgpWriteOptions { Now = PgpBenchKeys.Now, Passwords = [Password], ForceSeipd1 = true });
        _message = output.ToArray();
    }

    [Benchmark]
    public int Ours()
    {
        using var output = new MemoryStream();
        PgpMessageReader.Read(new MemoryStream(_message, writable: false), output, new PgpReadOptions { Now = PgpBenchKeys.Now, MessagePasswords = [Password] });
        return (int)output.Length;
    }

    [Benchmark]
    public int BouncyCastle()
    {
        using var input = new MemoryStream(_message, writable: false);
        var factory = new PgpObjectFactory(input);
        var list = (PgpEncryptedDataList)factory.NextPgpObject();
        var pbe = (PgpPbeEncryptedData)list[0];
        using Stream clear = pbe.GetDataStream("bench password".ToCharArray());
        var inner = new PgpObjectFactory(clear);
        var lit = (PgpLiteralData)inner.NextPgpObject();
        using var output = new MemoryStream();
        lit.GetInputStream().CopyTo(output);
        if (!pbe.Verify())
        {
            throw new InvalidDataException("integrity check failed");
        }

        return (int)output.Length;
    }
}
