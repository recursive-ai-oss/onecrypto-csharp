using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Internal;

namespace RecursiveAI.OneCrypto.Primitives.Fallback;

/// <summary>
/// ECDSA signature verification (FIPS 186-5 section 6.4.2, SEC 1 section 4.1.4) on short Weierstrass curves y^2 = x^3 + ax + b over a
/// prime field, for platforms whose cryptography cannot do it: the browser, and macOS for the Brainpool curves. Verify-only: it
/// touches the public key, the message digest and the signature, all public, so it uses <see cref="BigInteger"/> and makes no
/// constant-time claim. There is no signing here, and none will be.
/// </summary>
internal static class EcdsaVerifier
{
    private static readonly Dictionary<EcCurve, Curve> s_curves = [];

    /// <summary>
    /// Verifies a signature over an already computed digest.
    /// </summary>
    /// <param name="curve">The curve.</param>
    /// <param name="publicKey">The public point, uncompressed (SEC 1 section 2.3.3): 0x04, x, y.</param>
    /// <param name="digest">The message digest; only its leftmost bits, as many as the group order has, are used (FIPS 186-5 section 6.4.1).</param>
    /// <param name="signature">The signature.</param>
    /// <param name="format">DER <c>SEQUENCE { r, s }</c> (strict DER) or fixed-width <c>r || s</c>.</param>
    /// <returns>True when the signature is valid; false for a bad or malformed signature.</returns>
    /// <exception cref="ArgumentException">The public key is not a valid point on the curve.</exception>
    public static bool VerifyHash(EcCurve curve, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature, DSASignatureFormat format)
    {
        Curve c = Get(curve);
        int size = c.FieldBytes;
        if (publicKey.Length != 1 + (2 * size) || publicKey[0] != 0x04)
        {
            throw new ArgumentException("The public key must be an uncompressed point.", nameof(publicKey));
        }

        BigInteger qx = ReadUnsigned(publicKey.Slice(1, size));
        BigInteger qy = ReadUnsigned(publicKey.Slice(1 + size, size));
        // SEC 1 section 3.2.2.1: coordinates in range and the point on the curve (the group order is prime, the cofactor 1).
        if (qx >= c.P || qy >= c.P || Mod((qy * qy) - ((((qx * qx) + c.A) * qx) + c.B), c.P) != 0)
        {
            throw new ArgumentException("The public key is not a point on the curve.", nameof(publicKey));
        }

        BigInteger r;
        BigInteger s;
        if (format == DSASignatureFormat.IeeeP1363FixedFieldConcatenation)
        {
            if (signature.Length != 2 * size)
            {
                return false;
            }

            r = ReadUnsigned(signature[..size]);
            s = ReadUnsigned(signature[size..]);
        }
        else if (!TryParseDer(signature, out r, out s))
        {
            return false;
        }

        // FIPS 186-5 section 6.4.2 step 1: 0 < r, s < n.
        if (r.Sign <= 0 || s.Sign <= 0 || r >= c.N || s >= c.N)
        {
            return false;
        }

        BigInteger e = ReadUnsigned(digest);
        long excess = ((long)digest.Length * 8) - c.N.GetBitLength();
        if (excess > 0)
        {
            e >>= (int)excess;
        }

        BigInteger w = BigInteger.ModPow(s, c.N - 2, c.N); // n is prime
        BigInteger u1 = Mod(e * w, c.N);
        BigInteger u2 = Mod(r * w, c.N);
        Point q = new(qx, qy, BigInteger.One);
        Point g = new(c.Gx, c.Gy, BigInteger.One);
        Point result = DoubleScalar(c, u1, g, u2, q);
        if (result.Z.IsZero)
        {
            return false;
        }

        // x = X / Z^2 mod p, then x mod n must equal r.
        BigInteger zInv = BigInteger.ModPow(result.Z, c.P - 2, c.P);
        BigInteger x = Mod(result.X * zInv % c.P * zInv, c.P);
        return Mod(x, c.N) == r;
    }

    // ---- signature encodings ----

    /// <summary>
    /// Reads <c>SEQUENCE { INTEGER r, INTEGER s }</c> in strict DER (X.690 section 10): definite minimal lengths, minimal positive
    /// INTEGERs, nothing after the SEQUENCE. Platform verifiers differ on BER leniency, so the dispatch applies this check too.
    /// </summary>
    internal static bool TryParseDer(ReadOnlySpan<byte> der, out BigInteger r, out BigInteger s)
    {
        r = default;
        s = default;
        if (der.Length < 8 || der[0] != 0x30)
        {
            return false;
        }

        int length = der[1];
        int header = 2;
        if (length >= 0x80)
        {
            if (length != 0x81 || der.Length < 3 || der[2] < 0x80)
            {
                return false; // longer than 255 bytes cannot be a signature here; 0x81 is only minimal from 128 up
            }

            length = der[2];
            header = 3;
        }

        if (der.Length != header + length)
        {
            return false;
        }

        ReadOnlySpan<byte> body = der[header..];
        return TryReadInteger(ref body, out r) && TryReadInteger(ref body, out s) && body.IsEmpty;
    }

    private static bool TryReadInteger(ref ReadOnlySpan<byte> data, out BigInteger value)
    {
        value = default;
        if (data.Length < 3 || data[0] != 0x02)
        {
            return false;
        }

        int length = data[1];
        if (length == 0 || length >= 0x80 || data.Length < 2 + length)
        {
            return false;
        }

        ReadOnlySpan<byte> content = data.Slice(2, length);
        if ((content[0] & 0x80) != 0)
        {
            return false; // negative
        }

        if (content[0] == 0 && length > 1 && (content[1] & 0x80) == 0)
        {
            return false; // not minimal
        }

        value = ReadUnsigned(content);
        data = data[(2 + length)..];
        return true;
    }

    private static BigInteger ReadUnsigned(ReadOnlySpan<byte> bytes) => new(bytes, isUnsigned: true, isBigEndian: true);

    // ---- group arithmetic: Jacobian coordinates (x = X / Z^2, y = Y / Z^3), Z = 0 for the point at infinity ----

    private readonly record struct Point(BigInteger X, BigInteger Y, BigInteger Z);

    private static BigInteger Mod(BigInteger value, BigInteger modulus)
    {
        BigInteger r = BigInteger.Remainder(value, modulus);
        return r.Sign < 0 ? r + modulus : r;
    }

    private static Point Double(Curve c, Point a)
    {
        if (a.Z.IsZero || a.Y.IsZero)
        {
            return new Point(BigInteger.One, BigInteger.One, BigInteger.Zero);
        }

        BigInteger p = c.P;
        BigInteger yy = a.Y * a.Y % p;
        BigInteger zz = a.Z * a.Z % p;
        BigInteger sq = 4 * a.X * yy % p;
        BigInteger m = Mod((3 * a.X * a.X) + (c.A * zz % p * zz), p);
        BigInteger x3 = Mod((m * m) - (2 * sq), p);
        BigInteger y3 = Mod((m * (sq - x3)) - (8 * yy % p * yy), p);
        BigInteger z3 = 2 * a.Y * a.Z % p;
        return new Point(x3, y3, z3);
    }

    private static Point Add(Curve c, Point a, Point b)
    {
        if (a.Z.IsZero)
        {
            return b;
        }

        if (b.Z.IsZero)
        {
            return a;
        }

        BigInteger p = c.P;
        BigInteger z1z1 = a.Z * a.Z % p;
        BigInteger z2z2 = b.Z * b.Z % p;
        BigInteger u1 = a.X * z2z2 % p;
        BigInteger u2 = b.X * z1z1 % p;
        BigInteger s1 = a.Y * b.Z % p * z2z2 % p;
        BigInteger s2 = b.Y * a.Z % p * z1z1 % p;
        if (u1 == u2)
        {
            // Same x: the same point (double it) or its negation (infinity).
            return s1 == s2 ? Double(c, a) : new Point(BigInteger.One, BigInteger.One, BigInteger.Zero);
        }

        BigInteger h = Mod(u2 - u1, p);
        BigInteger rr = Mod(s2 - s1, p);
        BigInteger h2 = h * h % p;
        BigInteger h3 = h * h2 % p;
        BigInteger v = u1 * h2 % p;
        BigInteger x3 = Mod((rr * rr) - h3 - (2 * v), p);
        BigInteger y3 = Mod((rr * (v - x3)) - (s1 * h3), p);
        BigInteger z3 = h * a.Z % p * b.Z % p;
        return new Point(x3, y3, z3);
    }

    // k1 * P1 + k2 * P2 by interleaved double-and-add (Shamir's trick); the scalars are public.
    private static Point DoubleScalar(Curve c, BigInteger k1, Point p1, BigInteger k2, Point p2)
    {
        Point sum = Add(c, p1, p2);
        Point acc = new(BigInteger.One, BigInteger.One, BigInteger.Zero);
        long bits = Math.Max(k1.GetBitLength(), k2.GetBitLength());
        for (long i = bits - 1; i >= 0; i--)
        {
            acc = Double(c, acc);
            bool b1 = !((k1 >> (int)i) & 1).IsZero;
            bool b2 = !((k2 >> (int)i) & 1).IsZero;
            if (b1 && b2)
            {
                acc = Add(c, acc, sum);
            }
            else if (b1)
            {
                acc = Add(c, acc, p1);
            }
            else if (b2)
            {
                acc = Add(c, acc, p2);
            }
        }

        return acc;
    }

    // ---- curve parameters ----

    private sealed class Curve(string p, string a, string b, string gx, string gy, string n)
    {
        public BigInteger P { get; } = Hex(p);

        public BigInteger A { get; } = Hex(a);

        public BigInteger B { get; } = Hex(b);

        public BigInteger Gx { get; } = Hex(gx);

        public BigInteger Gy { get; } = Hex(gy);

        public BigInteger N { get; } = Hex(n);

        public int FieldBytes => (int)((P.GetBitLength() + 7) / 8);

        private static BigInteger Hex(string s) => BigInteger.Parse("0" + s, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
    }

    private static Curve Get(EcCurve curve)
    {
        lock (s_curves)
        {
            if (!s_curves.TryGetValue(curve, out Curve? c))
            {
                c = Create(curve);
                s_curves[curve] = c;
            }

            return c;
        }
    }

    // NIST curves: the parameters of RFC 5903 section 3 (the same curves as SP 800-186), with a = -3; Brainpool: RFC 5639 section 3. All have cofactor 1.
    private static Curve Create(EcCurve curve) => curve switch
    {
        EcCurve.NistP256 => new(
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
        EcCurve.NistP384 => new(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
            "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"),
        EcCurve.NistP521 => new(
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
            "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"),
        EcCurve.BrainpoolP256r1 => new(
            "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
            "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
            "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
            "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
            "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
            "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"),
        EcCurve.BrainpoolP384r1 => new(
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
            "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
            "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
            "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
            "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565"),
        EcCurve.BrainpoolP512r1 => new(
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
            "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
            "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
            "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
            "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069"),
        _ => throw new ArgumentOutOfRangeException(nameof(curve)),
    };
}
