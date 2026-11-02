using System.Numerics;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Keys.Pkcs11;

/// <summary>Builds <see cref="PublicKeyInfo"/> values from the attributes of PKCS #11 public key objects (v3.1 §6.3.3 for RSA, §6.3.4 for EC and EdDSA).</summary>
internal static class Pkcs11PublicKeys
{
    private const string EcPublicKey = "1.2.840.10045.2.1";
    private const string RsaEncryption = "1.2.840.113549.1.1.1";

    internal static byte[] OidDer(string dotted) => DerWriter.Oid(dotted);

    /// <summary>The key from the modulus and exponent (RSA) or the EC parameters and point; null when the object has not got the attributes for its type.</summary>
    internal static PublicKeyInfo? FromObject(Pkcs11KeyType type, byte[]? modulus, byte[]? exponent, byte[]? ecParams, byte[]? ecPoint)
    {
        switch (type)
        {
            case Pkcs11KeyType.Rsa when modulus is { Length: > 0 } && exponent is { Length: > 0 }:
                return Spki(DerWriter.Sequence(
                    DerWriter.Sequence(DerWriter.Oid(RsaEncryption), DerWriter.Null()),
                    BitString(DerWriter.Sequence(DerWriter.UnsignedInteger(modulus), DerWriter.UnsignedInteger(exponent)))));
            case Pkcs11KeyType.EllipticCurve or Pkcs11KeyType.EdwardsCurve when ecParams is { Length: > 0 } && ecPoint is { Length: > 0 }:
                string? edOid = EdwardsOid(ecParams);
                if (edOid is not null)
                {
                    int len = edOid == "1.3.101.112" ? 32 : 57;
                    byte[]? ep = Point(ecPoint, len);
                    return ep is null ? null : Spki(DerWriter.Sequence(DerWriter.Sequence(DerWriter.Oid(edOid)), BitString(ep)));
                }

                if (CurveOf(ecParams) is not { } curve)
                {
                    return null;
                }

                byte[]? point = Point(ecPoint, 1 + (2 * curve.FieldBytes));
                return point is null ? null : Spki(DerWriter.Sequence(DerWriter.Sequence(DerWriter.Oid(EcPublicKey), ecParams), BitString(point)));
            default:
                return null;
        }
    }

    /// <summary>The field size in octets and dotted identifier of a named curve given as CKA_EC_PARAMS (an encoded OID, §6.3.4), or null.</summary>
    internal static (string Oid, int FieldBytes)? CurveOf(byte[] ecParams)
    {
        var r = new Asn1Reader(ecParams, Asn1Rules.Ber);
        if (!r.TryReadObjectIdentifier(out string oid))
        {
            return null;
        }

        return oid switch
        {
            "1.2.840.10045.3.1.7" => (oid, 32),
            "1.3.132.0.34" => (oid, 48),
            "1.3.132.0.35" => (oid, 66),
            "1.3.36.3.3.2.8.1.1.7" => (oid, 32),
            "1.3.36.3.3.2.8.1.1.11" => (oid, 48),
            "1.3.36.3.3.2.8.1.1.13" => (oid, 64),
            _ => null,
        };
    }

    // Ed25519 and Ed448 parameters come as the curve OID or, in v3.0, as a PrintableString curve name (§6.3.4: "edwards25519", "edwards448").
    private static string? EdwardsOid(byte[] ecParams)
    {
        if (ecParams.AsSpan().SequenceEqual(new byte[] { 0x06, 0x03, 0x2B, 0x65, 0x70 }))
        {
            return "1.3.101.112";
        }

        if (ecParams.AsSpan().SequenceEqual(new byte[] { 0x06, 0x03, 0x2B, 0x65, 0x71 }))
        {
            return "1.3.101.113";
        }

        if (ecParams.Length > 2 && ecParams[0] == 0x13)
        {
            string name = System.Text.Encoding.ASCII.GetString(ecParams, 2, ecParams.Length - 2).ToLowerInvariant();
            return name.Contains("25519", StringComparison.Ordinal) && name.Contains("edwards", StringComparison.Ordinal) ? "1.3.101.112"
                : name.Contains("ed25519", StringComparison.Ordinal) ? "1.3.101.112"
                : name.Contains("448", StringComparison.Ordinal) && name.Contains("ed", StringComparison.Ordinal) ? "1.3.101.113"
                : null;
        }

        return null;
    }

    // CKA_EC_POINT is the point as a DER OCTET STRING (§6.3.4); some modules return the bare point. The expected length tells the two apart
    // (a bare point starting 0x04 could otherwise be read as a short OCTET STRING).
    private static byte[]? Point(byte[] value, int expected)
    {
        if (value.Length == expected)
        {
            return value;
        }

        var r = new Asn1Reader(value, Asn1Rules.Ber);
        return r.TryReadOctetString(out ReadOnlySpan<byte> inner) && inner.Length == expected ? inner.ToArray() : null;
    }

    // What a token reports about a key is not trusted to be well formed: an object that does not make a public key is simply not a source of one.
    private static PublicKeyInfo? Spki(byte[] encoded) => PublicKeyInfo.TryParse(encoded, out PublicKeyInfo? key) ? key : null;

    private static byte[] BitString(byte[] content) => DerWriter.Tlv(0x03, [[0x00], content]);

    /// <summary>The big-endian magnitude of an RSA public exponent or modulus as an integer, for logs only.</summary>
    internal static BigInteger Integer(byte[] magnitude) => new(magnitude, isUnsigned: true, isBigEndian: true);
}
