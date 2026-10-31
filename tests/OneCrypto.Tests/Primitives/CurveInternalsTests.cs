using System.Numerics;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Tests.Primitives;

/// <summary>Checks the arithmetic underneath the curves against BigInteger (test code only), and the argument and edge handling of the public API.</summary>
public class CurveInternalsTests
{
    private static readonly BigInteger L25519 = (BigInteger.One << 252) + BigInteger.Parse("27742317777372353535851937790883648493");
    private static readonly BigInteger L448 = (BigInteger.One << 446) - BigInteger.Parse("13818066809895115352007386748515426880336692474882178609894547503885");
    private static readonly BigInteger P25519 = (BigInteger.One << 255) - 19;
    private static readonly BigInteger P448 = (BigInteger.One << 448) - (BigInteger.One << 224) - 1;

    private static BigInteger Int(ReadOnlySpan<byte> le) => new(le, isUnsigned: true, isBigEndian: false);

    private static byte[] Bytes(BigInteger v, int len)
    {
        byte[] b = new byte[len];
        v.TryWriteBytes(b, out _, isUnsigned: true, isBigEndian: false);
        return b;
    }

    [Fact]
    public void ScalarReduceAndMulAddMatchBigInteger()
    {
        foreach ((ScalarField f, BigInteger l, int wide, int n) in new[] { (Ed25519Scalar.Field, L25519, 64, 4), (Ed448Scalar.Field, L448, 114, 7) })
        {
            for (int i = 0; i < 200; i++)
            {
                byte[] x = RandomNumberGenerator.GetBytes(wide);
                if (i == 0) { Array.Fill(x, (byte)0xff); }
                if (i == 1) { Array.Clear(x); }
                ulong[] r = new ulong[n];
                f.ReduceWide(x, r);
                byte[] rb = new byte[8 * n];
                ScalarField.Store(r, rb);
                Assert.Equal(Int(x) % l, Int(rb));

                // a·b + c with a up to 2^(64 n) - 1 (like a clamped secret), b and c reduced.
                byte[] ab = RandomNumberGenerator.GetBytes(8 * n);
                BigInteger a = Int(ab);
                BigInteger b = Int(RandomNumberGenerator.GetBytes(wide)) % l;
                BigInteger c = Int(RandomNumberGenerator.GetBytes(wide)) % l;
                ulong[] al = new ulong[n], bl = new ulong[n], cl = new ulong[n], o = new ulong[n];
                ScalarField.Load(ab, al);
                ScalarField.Load(Bytes(b, 8 * n), bl);
                ScalarField.Load(Bytes(c, 8 * n), cl);
                f.MulAdd(al, bl, cl, o);
                byte[] ob = new byte[8 * n];
                ScalarField.Store(o, ob);
                Assert.Equal((a * b + c) % l, Int(ob));
            }
        }
    }

    [Fact]
    public void FieldArithmeticMatchesBigInteger()
    {
        for (int i = 0; i < 300; i++)
        {
            byte[] xa = RandomNumberGenerator.GetBytes(32), xb = RandomNumberGenerator.GetBytes(32);
            if (i == 0) { Array.Fill(xa, (byte)0xff); Array.Fill(xb, (byte)0xff); }
            xa[31] &= 0x7f;
            xb[31] &= 0x7f;
            BigInteger a = Int(xa), b = Int(xb);
            Fe25519 fa = Fe25519.FromBytes(xa), fb = Fe25519.FromBytes(xb);
            byte[] o = new byte[32];
            Fe25519.Mul(fa, fb).ToBytes(o);
            Assert.Equal(a * b % P25519, Int(o));
            Fe25519.Square(fa).ToBytes(o);
            Assert.Equal(a * a % P25519, Int(o));
            Fe25519.Sub(fa, fb).ToBytes(o);
            Assert.Equal((((a - b) % P25519) + P25519) % P25519, Int(o));
            Fe25519.Add(fa, fb).ToBytes(o);
            Assert.Equal((a + b) % P25519, Int(o));
            Fe25519.Invert(fa).ToBytes(o);
            Assert.Equal(a % P25519 == 0 ? 0 : BigInteger.ModPow(a, P25519 - 2, P25519), Int(o));

            byte[] ya = RandomNumberGenerator.GetBytes(56), yb = RandomNumberGenerator.GetBytes(56);
            if (i == 0) { Array.Fill(ya, (byte)0xff); Array.Fill(yb, (byte)0xff); }
            BigInteger c = Int(ya), d = Int(yb);
            Fe448 fc = Fe448.FromBytes(ya), fd = Fe448.FromBytes(yb);
            byte[] q = new byte[56];
            Fe448.Mul(fc, fd).ToBytes(q);
            Assert.Equal(c * d % P448, Int(q));
            Fe448.Square(fc).ToBytes(q);
            Assert.Equal(c * c % P448, Int(q));
            Fe448.Sub(fc, fd).ToBytes(q);
            Assert.Equal((((c - d) % P448) + P448) % P448, Int(q));
            Fe448.Add(fc, fd).ToBytes(q);
            Assert.Equal((c + d) % P448, Int(q));
            Fe448.Invert(fc).ToBytes(q);
            Assert.Equal(c % P448 == 0 ? 0 : BigInteger.ModPow(c, P448 - 2, P448), Int(q));
        }
    }

    [Fact]
    public void BasePointsHaveTheGroupOrder()
    {
        // [L]B is the identity (encoded as y = 1, x even) and [L - 1]B = -B.
        byte[] id25519 = new byte[32]; id25519[0] = 1;
        Ge25519 b = Ge25519Ops.Base();
        byte[] enc = new byte[32];
        Ge25519Ops.Encode(Ge25519Ops.ScalarMultVartime(Bytes(L25519, 32), b), enc);
        Assert.Equal(Convert.ToHexString(id25519), Convert.ToHexString(enc));

        byte[] id448 = new byte[57]; id448[0] = 1;
        Ge448 b4 = Ge448Ops.Base();
        byte[] enc4 = new byte[57];
        Ge448Ops.Encode(Ge448Ops.ScalarMultVartime(Bytes(L448, 56), b4), enc4);
        Assert.Equal(Convert.ToHexString(id448), Convert.ToHexString(enc4));

        // The constant-time fixed-base path agrees with the variable-time path for random scalars.
        for (int i = 0; i < 20; i++)
        {
            byte[] k = Bytes(Int(RandomNumberGenerator.GetBytes(64)) % L25519, 32);
            byte[] e1 = new byte[32], e2 = new byte[32];
            Ge25519Ops.Encode(Ge25519Ops.ScalarMultBase(k), e1);
            Ge25519Ops.Encode(Ge25519Ops.ScalarMultVartime(k, b), e2);
            Assert.Equal(Convert.ToHexString(e2), Convert.ToHexString(e1));
            byte[] k4 = Bytes(Int(RandomNumberGenerator.GetBytes(114)) % L448, 56);
            byte[] f1 = new byte[57], f2 = new byte[57];
            Ge448Ops.Encode(Ge448Ops.ScalarMultBase(k4), f1);
            Ge448Ops.Encode(Ge448Ops.ScalarMultVartime(k4, b4), f2);
            Assert.Equal(Convert.ToHexString(f2), Convert.ToHexString(f1));
        }
    }

    [Fact]
    public void VerifyNeverThrowsOnMalformedInput()
    {
        byte[] key = new byte[32], sig = new byte[64];
        Assert.False(Ed25519.Verify(key.AsSpan(0, 31), [], sig));
        Assert.False(Ed25519.Verify(key, [], sig.AsSpan(0, 63)));
        Assert.False(Ed25519.VerifyWithContext(key, [], [], sig));
        Assert.False(Ed25519.VerifyWithContext(key, [], new byte[256], sig));
        Assert.False(Ed25519.VerifyHash(key, new byte[63], [], sig));
        Assert.False(Ed448.Verify(new byte[57], [], new byte[256], new byte[114]));
        Assert.False(Ed448.Verify(new byte[56], [], [], new byte[114]));
        Assert.False(Ed448.Verify(new byte[57], [], [], new byte[113]));
        // A signature with the top bits of the 57th S byte set must be refused, not read modulo anything.
        using var k = Ed448PrivateKey.Generate();
        byte[] s = new byte[114];
        Assert.True(k.TrySign("m"u8, [], s, out _));
        s[113] = 1;
        Assert.False(k.PublicKey.Verify("m"u8, [], s));
    }

    [Fact]
    public void SigningArgumentChecks()
    {
        byte[] seed = new byte[32], sig = new byte[64];
        Assert.Throws<ArgumentException>(() => Ed25519.TrySign(new byte[31], [], new byte[64], out _));
        Assert.Throws<ArgumentException>(() => Ed25519.TrySignWithContext(new byte[32], [], [], new byte[64], out _));
        Assert.Throws<ArgumentException>(() => Ed25519.TrySignPrehashed(new byte[32], [], new byte[256], new byte[64], out _));
        Assert.False(Ed25519.TrySign(seed, [], sig.AsSpan(0, 63), out int n));
        Assert.Equal(0, n);
        Assert.Throws<ArgumentException>(() => Ed448.TrySign(new byte[57], [], new byte[256], new byte[114], out _));
        Assert.Throws<ArgumentException>(() => X25519.ScalarMult(new byte[31], new byte[32], new byte[32]));
        Assert.Throws<ArgumentException>(() => X448.ScalarMult(new byte[56], new byte[57], new byte[56]));
        Assert.False(Ed448PublicKey.TryFromBytes(new byte[56], out _));
    }

    [Fact]
    public void ContextsAndFlavoursDoNotCrossVerify()
    {
        byte[] seed = RandomNumberGenerator.GetBytes(32), pub = new byte[32], sig = new byte[64];
        Ed25519.DerivePublicKey(seed, pub);
        Assert.True(Ed25519.TrySignWithContext(seed, "m"u8, "a"u8, sig, out _));
        Assert.True(Ed25519.VerifyWithContext(pub, "m"u8, "a"u8, sig));
        Assert.False(Ed25519.VerifyWithContext(pub, "m"u8, "b"u8, sig));
        Assert.False(Ed25519.VerifyPrehashed(pub, "m"u8, "a"u8, sig));
        Assert.False(Ed25519.Verify(pub, "m"u8, sig));

        byte[] seed4 = RandomNumberGenerator.GetBytes(57), pub4 = new byte[57], sig4 = new byte[114];
        Ed448.DerivePublicKey(seed4, pub4);
        Assert.True(Ed448.TrySign(seed4, "m"u8, "a"u8, sig4, out _));
        Assert.False(Ed448.VerifyPrehashed(pub4, "m"u8, "a"u8, sig4));
        Assert.False(Ed448.Verify(pub4, "m"u8, "b"u8, sig4));
        Assert.True(Ed448.Verify(pub4, "m"u8, "a"u8, sig4));
    }

    [Fact]
    public void PrivateKeyIsZeroedOnDispose()
    {
        var key = X25519PrivateKey.Generate();
        byte[] copy = new byte[32];
        key.Export(copy);
        Assert.Contains(copy, b => b != 0);
        key.Dispose();
        Assert.Throws<ObjectDisposedException>(() => key.Export(copy));
    }
}
