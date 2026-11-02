using System.Formats.Asn1;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>
/// Compares the public key of a key that lives elsewhere with an OpenPGP key packet, so a message is never signed or opened with a key that belongs to another certificate.
/// Only public values are compared, so the comparison need not be constant time.
/// </summary>
internal static class ExternalKeyPairing
{
    internal static void Require(KeyPacket packet, PublicKeyInfo external)
    {
        PublicKeyMaterial m = packet.Material;
        switch (packet.Algorithm)
        {
            case PublicKeyAlgorithm.Rsa or PublicKeyAlgorithm.RsaEncryptOnly or PublicKeyAlgorithm.RsaSignOnly:
                Expect(external.KeyAlgorithm is KeyAlgorithm.Rsa or KeyAlgorithm.RsaPss or KeyAlgorithm.RsaOaep, packet, "an RSA key");
                Expect(SameRsa(m.Values[0].Span, m.Values[1].Span, external.KeyBits.Span), packet, "the same RSA modulus and exponent");
                break;
            case PublicKeyAlgorithm.Ecdsa or PublicKeyAlgorithm.Ecdh when !SignatureEngineCurve25519(m):
                Expect(external.KeyAlgorithm == KeyAlgorithm.EllipticCurve, packet, "an elliptic-curve key");
                string oid = external.CurveOid ?? string.Empty;
                Expect(oid.Length > 0 && DerWriter.Oid(oid).AsSpan(2).SequenceEqual(m.CurveOid.Span), packet, "the same curve");
                Expect(external.KeyBits.Span.SequenceEqual(m.Values[0].Span), packet, "the same point");
                break;
            case PublicKeyAlgorithm.Ecdh: // Curve25519 in the legacy ECDH form: 0x40 and the u-coordinate
                Expect(external.KeyAlgorithm == KeyAlgorithm.X25519, packet, "an X25519 key");
                Expect(Prefixed(m.Values[0].Span, external.KeyBits.Span), packet, "the same X25519 key");
                break;
            case PublicKeyAlgorithm.EdDsaLegacy: // Ed25519 as a 0x40 and the 32-octet key
                Expect(external.KeyAlgorithm == KeyAlgorithm.Ed25519, packet, "an Ed25519 key");
                Expect(Prefixed(m.Values[0].Span, external.KeyBits.Span), packet, "the same Ed25519 key");
                break;
            case PublicKeyAlgorithm.X25519 or PublicKeyAlgorithm.X448 or PublicKeyAlgorithm.Ed25519 or PublicKeyAlgorithm.Ed448:
                KeyAlgorithm want = packet.Algorithm switch
                {
                    PublicKeyAlgorithm.X25519 => KeyAlgorithm.X25519,
                    PublicKeyAlgorithm.X448 => KeyAlgorithm.X448,
                    PublicKeyAlgorithm.Ed25519 => KeyAlgorithm.Ed25519,
                    _ => KeyAlgorithm.Ed448,
                };
                Expect(external.KeyAlgorithm == want, packet, "a " + want + " key");
                Expect(external.KeyBits.Span.SequenceEqual(m.Values[0].Span), packet, "the same public key");
                break;
            default:
                throw new PgpException(PgpFailure.Unsupported, $"An external key cannot be attached to a {packet.Algorithm} key packet: its pairing cannot be checked.");
        }
    }

    private static bool SignatureEngineCurve25519(PublicKeyMaterial m) => SignatureEngine.Curves.IsCurve25519(m.CurveOid.Span);

    private static bool Prefixed(ReadOnlySpan<byte> packetPoint, ReadOnlySpan<byte> key) =>
        packetPoint.Length == key.Length + 1 && packetPoint[0] == 0x40 && packetPoint[1..].SequenceEqual(key);

    private static bool SameRsa(ReadOnlySpan<byte> n, ReadOnlySpan<byte> e, ReadOnlySpan<byte> rsaPublicKey)
    {
        try
        {
            var seq = new AsnReader(rsaPublicKey.ToArray(), AsnEncodingRules.BER).ReadSequence();
            ReadOnlySpan<byte> en = Strip(seq.ReadIntegerBytes().Span);
            ReadOnlySpan<byte> ee = Strip(seq.ReadIntegerBytes().Span);
            return en.SequenceEqual(Strip(n)) && ee.SequenceEqual(Strip(e));
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    private static ReadOnlySpan<byte> Strip(ReadOnlySpan<byte> v)
    {
        while (v.Length > 1 && v[0] == 0)
        {
            v = v[1..];
        }

        return v;
    }

    private static void Expect(bool ok, KeyPacket packet, string what)
    {
        if (!ok)
        {
            throw new PgpException(PgpFailure.KeyMismatch, $"The external key is not the private half of key {packet.FingerprintHex}: the key packet needs {what}.");
        }
    }
}
