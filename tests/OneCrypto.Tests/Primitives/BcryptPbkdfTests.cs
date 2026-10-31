using System.Buffers.Binary;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Tests.Primitives;

/// <summary>
/// bcrypt-pbkdf against ssh-keygen: keys it encrypted (testdata/bcrypt-pbkdf, written by tools/gen-bcrypt-pbkdf-fixtures.sh) must
/// decrypt with the key and IV our derivation produces. A wrong construction cannot pass: the two check integers at the start of
/// the private section only agree after a correct decryption.
/// </summary>
public class BcryptPbkdfTests
{
    public static TheoryData<string, string> Keys => new()
    {
        { "ed25519-aes256-ctr-a16-correct_horse.key", "correct horse" },
        { "ed25519-aes256-ctr-a1-x.key", "x" },
        { "ed25519-aes128-ctr-a8-battery_staple.key", "battery staple" },
        { "ed25519-aes256-ctr-a64-p__ssw__rd.key", "pässwörd" },
        { "ecdsa-aes256-cbc-a5-longer_passphrase_with_spaces_and_a_very_long_tail_0123456789.key", "longer passphrase with spaces and a very long tail 0123456789" },
    };

    [Theory]
    [MemberData(nameof(Keys))]
    public void DerivedKeyDecryptsAKeyWrittenBySshKeygen(string file, string passphrase)
    {
        byte[] blob = ReadKey(file);
        var r = new Reader(blob);
        Assert.Equal("openssh-key-v1\0"u8.ToArray(), r.Take(15));
        string cipher = System.Text.Encoding.ASCII.GetString(r.String());
        Assert.Equal("bcrypt", System.Text.Encoding.ASCII.GetString(r.String()));
        var options = new Reader(r.String());
        byte[] salt = options.String();
        int rounds = (int)options.UInt32();
        Assert.Equal(1u, r.UInt32());
        r.String(); // public key
        byte[] encrypted = r.String();

        (int keyLength, int ivLength) = cipher.StartsWith("aes256", StringComparison.Ordinal) ? (32, 16) : (16, 16);
        byte[] material = BcryptPbkdf.DeriveKey(System.Text.Encoding.UTF8.GetBytes(passphrase), salt, rounds, keyLength + ivLength);

        using var aes = Aes.Create();
        aes.Key = material[..keyLength];
        byte[] iv = material[keyLength..];
        byte[] clear = cipher.EndsWith("-cbc", StringComparison.Ordinal)
            ? aes.DecryptCbc(encrypted, iv, PaddingMode.None)
            : CtrDecrypt(aes, iv, encrypted);

        // OpenSSH, PROTOCOL.key: the section starts with two equal random 32-bit integers.
        Assert.Equal(BinaryPrimitives.ReadUInt32BigEndian(clear), BinaryPrimitives.ReadUInt32BigEndian(clear.AsSpan(4)));
    }

    [Fact]
    public void WrongPassphraseDoesNotDecrypt()
    {
        byte[] blob = ReadKey("ed25519-aes256-ctr-a1-x.key");
        var r = new Reader(blob);
        r.Take(15);
        r.String();
        r.String();
        var options = new Reader(r.String());
        byte[] salt = options.String();
        int rounds = (int)options.UInt32();
        r.UInt32();
        r.String();
        byte[] encrypted = r.String();
        byte[] material = BcryptPbkdf.DeriveKey("y"u8, salt, rounds, 48);
        using var aes = Aes.Create();
        aes.Key = material[..32];
        byte[] clear = CtrDecrypt(aes, material[32..], encrypted);
        Assert.NotEqual(BinaryPrimitives.ReadUInt32BigEndian(clear), BinaryPrimitives.ReadUInt32BigEndian(clear.AsSpan(4)));
    }

    [Fact]
    public void OutputLengthsShareAPrefixOnlyWithinOneStride()
    {
        // A key of 1..32 bytes comes from one block, so shorter requests are prefixes of the 32-byte one.
        byte[] salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        byte[] k32 = BcryptPbkdf.DeriveKey("pw"u8, salt, 3, 32);
        Assert.Equal(k32[..20], BcryptPbkdf.DeriveKey("pw"u8, salt, 3, 20));

        // Beyond 32 bytes the bytes are dealt out round-robin, so the first 32 bytes change.
        byte[] k48 = BcryptPbkdf.DeriveKey("pw"u8, salt, 3, 48);
        Assert.NotEqual(k32, k48[..32]);
        Assert.Equal(48, k48.Length);
    }

    [Fact]
    public void BadParametersAreTyped()
    {
        Assert.Throws<ArgumentException>(() => BcryptPbkdf.DeriveKey("p"u8, [], 1, 32));
        Assert.Throws<ArgumentOutOfRangeException>(() => BcryptPbkdf.DeriveKey("p"u8, "salt"u8, 0, 32));
        Assert.Throws<ArgumentOutOfRangeException>(() => BcryptPbkdf.DeriveKey("p"u8, "salt"u8, 1, 1025));
        var e = Assert.Throws<KdfLimitExceededException>(() => BcryptPbkdf.DeriveKey("p"u8, "salt"u8, 1_000_000, 32));
        Assert.Equal("rounds", e.Parameter);
    }

    // Build output lives outside the checkout, so testdata is found relative to this source file.
    private static byte[] ReadKey(string file, [System.Runtime.CompilerServices.CallerFilePath] string here = "")
    {
        string root = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(here)!, "..", "..", ".."));
        string pem = File.ReadAllText(Path.Combine(root, "testdata", "bcrypt-pbkdf", file));
        string body = string.Concat(pem.Split('\n').Where(l => !l.StartsWith("-----", StringComparison.Ordinal)));
        return Convert.FromBase64String(body);
    }

    // AES-CTR with a 128-bit big-endian counter, built on the platform's single-block ECB.
    private static byte[] CtrDecrypt(Aes aes, byte[] iv, byte[] data)
    {
        byte[] counter = (byte[])iv.Clone();
        byte[] result = new byte[data.Length];
        byte[] stream = new byte[16];
        for (int i = 0; i < data.Length; i += 16)
        {
            aes.EncryptEcb(counter, stream, PaddingMode.None);
            for (int j = 0; j < 16 && i + j < data.Length; j++)
            {
                result[i + j] = (byte)(data[i + j] ^ stream[j]);
            }

            for (int j = 15; j >= 0 && ++counter[j] == 0; j--)
            {
            }
        }

        return result;
    }

    private sealed class Reader(byte[] data)
    {
        private int _position;

        public byte[] Take(int n)
        {
            byte[] r = data[_position..(_position + n)];
            _position += n;
            return r;
        }

        public uint UInt32()
        {
            uint v = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(_position));
            _position += 4;
            return v;
        }

        public byte[] String() => Take((int)UInt32());
    }
}
