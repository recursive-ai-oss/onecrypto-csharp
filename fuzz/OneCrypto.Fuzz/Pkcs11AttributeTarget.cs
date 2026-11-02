using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys.Pkcs11;

namespace OneCrypto.Fuzz;

/// <summary>
/// The attributes a token reports for a key object (modulus, exponent, EC parameters, EC point) turned into a public key. A module can return anything
/// for them, so the answer must be a key or nothing: no exception may escape, and a key that comes out must be one the library can read back.
/// </summary>
internal static class Pkcs11AttributeTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
        {
            return;
        }

        Pkcs11KeyType type = (data[0] % 3) switch { 0 => Pkcs11KeyType.Rsa, 1 => Pkcs11KeyType.EllipticCurve, _ => Pkcs11KeyType.EdwardsCurve };
        int split = data[1] % (data.Length - 1);
        ReadOnlySpan<byte> rest = data[2..];
        int first = Math.Min(split, rest.Length);
        byte[] a = rest[..first].ToArray();
        byte[] b = rest[first..].ToArray();
        PublicKeyInfo? key = type == Pkcs11KeyType.Rsa
            ? Pkcs11PublicKeys.FromObject(type, a, b, null, null)
            : Pkcs11PublicKeys.FromObject(type, null, null, a, b);
        if (key is not null && !PublicKeyInfo.TryParse(key.Encoded, out _))
        {
            throw new InvalidOperationException("a public key built from token attributes did not parse back");
        }
    }

    public static IEnumerable<byte[]> Seeds()
    {
        // RSA: modulus, exponent. EC P-256: encoded OID, point as an OCTET STRING. Ed25519: encoded OID, the bare point.
        byte[] n = new byte[256];
        n[0] = 0xC1;
        n[^1] = 0x01;
        yield return Join(0, n, [0x01, 0x00, 0x01]);
        byte[] point = new byte[65];
        point[0] = 4;
        point[1] = 1;
        point[33] = 2;
        yield return Join(1, [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07], [0x04, 0x41, .. point]);
        yield return Join(2, [0x06, 0x03, 0x2B, 0x65, 0x70], new byte[32]);
    }

    private static byte[] Join(byte kind, byte[] a, byte[] b) => [kind, (byte)Math.Min(a.Length, 255), .. a, .. b];
}
