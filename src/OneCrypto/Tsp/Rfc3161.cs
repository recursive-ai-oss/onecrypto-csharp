using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace RecursiveAI.OneCrypto.Tsp;

/// <summary>
/// The client side of RFC 3161 that needs no network: building a <c>TimeStampReq</c>, and taking a <c>TimeStampResp</c>
/// (or a bare token) apart to check it before it is embedded. Whether the authority is trusted is the verifier's question.
/// </summary>
internal static class Rfc3161
{
    /// <summary>Tokens and responses larger than this are refused before they are parsed.</summary>
    public const int MaxResponseBytes = 1 << 20;

    private static string HashOid(HashAlgorithmName hash) =>
        hash == HashAlgorithmName.SHA256 ? KnownOids.Sha256
        : hash == HashAlgorithmName.SHA384 ? KnownOids.Sha384
        : hash == HashAlgorithmName.SHA512 ? KnownOids.Sha512
        : throw new ArgumentException("Only SHA-256, SHA-384 and SHA-512 are supported.", nameof(hash));

    /// <summary>
    /// <c>TimeStampReq ::= SEQUENCE { version 1, messageImprint, nonce, certReq TRUE }</c> (RFC 3161 §2.4.1). The certificate is
    /// requested so the token is self-contained.
    /// </summary>
    public static byte[] BuildRequest(HashAlgorithmName hash, ReadOnlySpan<byte> imprint, ReadOnlySpan<byte> nonce)
    {
        byte[] messageImprint = DerWriter.Sequence(DerWriter.Sequence(DerWriter.Oid(HashOid(hash))), DerWriter.OctetString(imprint));
        return DerWriter.Sequence(DerWriter.SignedInteger(1), messageImprint, DerWriter.UnsignedInteger(nonce), DerWriter.Boolean(true));
    }

    /// <summary>
    /// Checks a response or token and returns the token (a CMS ContentInfo, as DER). Fails with a message when the status is not granted,
    /// the structure is malformed, the imprint differs from the one sent, or the nonce is missing or different.
    /// </summary>
    public static bool TryExtractToken(byte[] data, HashAlgorithmName hash, ReadOnlySpan<byte> imprint, ReadOnlySpan<byte> nonce, out byte[] token, out string error)
    {
        token = [];
        if (data.Length == 0 || data.Length > MaxResponseBytes)
        {
            error = data.Length == 0 ? "The time-stamp callback returned nothing." : "The time-stamp response is larger than 1 MiB.";
            return false;
        }

        ReadOnlyMemory<byte> tokenBytes;
        try
        {
            var r = new Asn1Reader(data, Asn1Rules.Ber);
            ReadOnlySpan<byte> whole = r.ReadEncodedValue();
            r.ThrowIfNotEmpty();
            Asn1Reader top = new Asn1Reader(whole, Asn1Rules.Ber).ReadSequence();
            if (top.PeekTag() == new Asn1Tag(Asn1Tags.ObjectIdentifier))
            {
                // A bare token: ContentInfo ::= SEQUENCE { contentType OID, content [0] }.
                tokenBytes = data;
            }
            else
            {
                // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo OPTIONAL }; PKIStatus 0 granted, 1 grantedWithMods.
                Asn1Reader status = top.ReadSequence();
                int code = status.ReadInt32();
                if (code > 1)
                {
                    error = $"The time-stamp authority refused the request (status {code}).";
                    return false;
                }

                if (!top.HasData)
                {
                    error = "The time-stamp response is granted but holds no token.";
                    return false;
                }

                tokenBytes = top.ReadEncodedValue().ToArray();
            }
        }
        catch (Asn1ParseException e)
        {
            error = "The time-stamp response is malformed: " + e.Message;
            return false;
        }

        if (!SignedData.TryParse(tokenBytes, out SignedData? sd) || sd!.Signers.Count == 0)
        {
            error = "The time-stamp token is not a valid CMS SignedData: it could not be read or it has no signer.";
            return false;
        }

        if (sd.EncapsulatedContentType != CmsOids.TstInfo || !sd.HasEncapsulatedContent)
        {
            error = "The time-stamp token does not hold a TSTInfo.";
            return false;
        }

        // TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime, accuracy?, ordering?, nonce?, tsa?, extensions? }
        byte[] echoed = [];
        bool hasNonce = false;
        try
        {
            Asn1Reader tst = new Asn1Reader(sd.EncapsulatedContent.Span, Asn1Rules.Ber).ReadSequence();
            tst.SkipValue();
            tst.SkipValue();
            Asn1Reader mi = tst.ReadSequence();
            AlgorithmIdentifier alg = AlgorithmIdentifier.Parse(mi.ReadEncodedValue().ToArray());
            ReadOnlySpan<byte> stamped = mi.ReadOctetString();
            if (alg.Oid != HashOid(hash) || !stamped.SequenceEqual(imprint))
            {
                error = "The time-stamp token stamps different data than was sent (message imprint mismatch).";
                return false;
            }

            tst.SkipValue();
            tst.SkipValue();
            while (tst.HasData)
            {
                if (tst.PeekTag() == new Asn1Tag(Asn1Tags.IntegerType))
                {
                    echoed = tst.ReadUnsignedIntegerBytes().ToArray();
                    hasNonce = true;
                    break;
                }

                tst.SkipValue();
            }
        }
        catch (Exception e) when (e is Asn1ParseException or X509ParseException)
        {
            error = "The TSTInfo in the time-stamp token is malformed.";
            return false;
        }

        // RFC 3161 §2.4.2: when the request carried a nonce the token must carry the same one.
        ReadOnlySpan<byte> sent = CmsRead.TrimZeros(nonce);
        if (!hasNonce || !CmsRead.TrimZeros(echoed).SequenceEqual(sent))
        {
            error = hasNonce ? "The time-stamp token echoes a different nonce." : "The time-stamp token does not echo the nonce of the request.";
            return false;
        }

        // PAdES wants the SignedData in /Contents as DER (ETSI EN 319 142-1); an authority may have used indefinite lengths.
        if (!BerToDer.TryConvert(tokenBytes, out token))
        {
            token = [];
            error = "The time-stamp token could not be re-encoded as DER.";
            return false;
        }

        error = string.Empty;
        return true;
    }
}
