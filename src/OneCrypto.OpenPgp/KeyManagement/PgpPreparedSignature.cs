using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Policy;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>
/// An OpenPGP signature made in two steps. <see cref="PrepareDetached"/> fixes the signature header and hashes the data; the public-key operation over
/// <see cref="ToSign"/> then runs anywhere (an <see cref="ISigningKey"/>, a token, another process or another day) and <see cref="Complete"/> checks the result
/// against the signer's public key and assembles the signature packet.
/// </summary>
/// <remarks>
/// The state serialises (<see cref="Encode"/>) as DER, versioned like <see cref="PreparedSignature"/>: <c>SEQUENCE { version INTEGER, purpose UTF8String
/// ("openpgp.signature"), signerKey OCTET STRING (the public key packet), type INTEGER, hash INTEGER, signedHeader OCTET STRING, unhashed OCTET STRING,
/// salt OCTET STRING, digest OCTET STRING }</c>. It holds the digest and the public key, never the data and never a private key. Version 6 and version 4 keys
/// of the RSA, ECDSA, EdDSA and Ed25519/Ed448 families are supported; the ML-DSA composites sign two components and are not.
/// </remarks>
public sealed class PgpPreparedSignature
{
    /// <summary>The version of the serialised form this library writes and reads.</summary>
    public const int FormatVersion = 1;

    /// <summary>The purpose label in the serialised state.</summary>
    public const string Purpose = "openpgp.signature";

    private readonly PendingSignature _pending;

    private PgpPreparedSignature(PendingSignature pending)
    {
        _pending = pending;
        Spec = SignatureMaterialBuilder.SpecFor(pending.Key, pending.Hash);
        Input = Spec.SignsDigest ? SigningInput.Digest : SigningInput.Message;
    }

    /// <summary>How <see cref="ToSign"/> is to be signed (RSA PKCS#1 v1.5 or ECDSA over the digest, Ed25519 or Ed448 over the digest as the message).</summary>
    public SignatureSpec Spec { get; }

    /// <summary>Whether the signer's operation takes <see cref="ToSign"/> as a digest or as a message.</summary>
    public SigningInput Input { get; }

    /// <summary>The octets the signer signs: the signature digest (RFC 9580 §5.2.4), including the version 6 salt.</summary>
    public ReadOnlyMemory<byte> ToSign => _pending.Digest;

    /// <summary>The hash the digest was made with.</summary>
    public PgpHashAlgorithm Hash => _pending.Hash;

    /// <summary>The signature type.</summary>
    public SignatureType Type => _pending.Type;

    /// <summary>The signer's public key packet.</summary>
    public KeyPacket Signer => _pending.Key;

    /// <summary>
    /// Phase one for a detached signature (type 0x00, or 0x01 for text) over <paramref name="data"/>.
    /// </summary>
    /// <param name="signer">The signing key's public side; a key with secret material is accepted and only its public part is used.</param>
    /// <param name="data">The data to sign. It is read to the end and not kept.</param>
    /// <param name="now">The signature creation time. There is no default clock.</param>
    /// <param name="text">True to sign canonical text (line endings as CR LF).</param>
    /// <param name="hash">The hash; chosen from the key when null.</param>
    /// <param name="policy">The policy for the hash and key size. <see cref="CryptoPolicy.Standard"/> when null.</param>
    /// <exception cref="PgpException">The key cannot sign, or the policy refuses the hash or key.</exception>
    public static PgpPreparedSignature PrepareDetached(PgpKey signer, Stream data, DateTimeOffset now, bool text = false, PgpHashAlgorithm? hash = null, CryptoPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(data);
        KeyPacket kp = signer.Packet is SecretKeyPacket sk ? sk.ToPublic() : signer.Packet;
        if (kp.Algorithm is PublicKeyAlgorithm.MlDsa65Ed25519 or PublicKeyAlgorithm.MlDsa87Ed448)
        {
            throw new PgpException(PgpFailure.Unsupported, "Two-phase signing is not available for the ML-DSA composites.");
        }

        SignatureMaterialBuilder.SpecFor(kp, PgpHashAlgorithm.Sha256);
        PendingSignature p = KeySignatures.Begin(kp, text ? SignatureType.Text : SignatureType.Binary, [], [], now, policy ?? CryptoPolicy.Standard, hash, h =>
        {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = data.Read(buf, 0, buf.Length)) > 0)
            {
                h.Append(buf.AsSpan(0, n));
            }
        });
        return new PgpPreparedSignature(p);
    }

    /// <summary>
    /// Phase two. Checks <paramref name="signature"/> (the signer's raw output for <see cref="ToSign"/> under <see cref="Spec"/>: the 64 or 114 octets of EdDSA, the
    /// PKCS#1 signature, or the ECDSA r and s concatenated) against the signer's public key and returns the signature packet.
    /// </summary>
    /// <exception cref="PgpException">The signature does not verify for this key and digest (<see cref="PgpFailure.MalformedMessage"/>).</exception>
    public byte[] Complete(ReadOnlySpan<byte> signature)
    {
        byte[] material;
        try
        {
            material = SignatureMaterialBuilder.Encode(_pending.Key.Algorithm, signature);
        }
        catch (ArgumentOutOfRangeException)
        {
            throw new PgpException(PgpFailure.MalformedMessage, "The signature has the wrong length for this key.");
        }

        SignaturePacket packet = _pending.Assemble(material);
        bool ok;
        try
        {
            ok = SignatureEngine.VerifyDigest(_pending.Key, packet, _pending.Digest);
        }
        catch (CryptographicException)
        {
            ok = false;
        }

        return ok ? packet.ToArray() : throw new PgpException(PgpFailure.MalformedMessage, "The signature does not verify against the signer's public key.");
    }

    /// <summary>Phase two with armor: the signature as an ASCII-armored <c>PGP SIGNATURE</c> block.</summary>
    public byte[] CompleteArmored(ReadOnlySpan<byte> signature)
    {
        byte[] binary = Complete(signature);
        using var ms = new MemoryStream();
        using (var armor = new ArmorWriteStream(ms, "PGP SIGNATURE", leaveOpen: true))
        {
            armor.Write(binary);
            armor.Complete();
        }

        return ms.ToArray();
    }

    /// <summary>Signs <see cref="ToSign"/> with <paramref name="key"/> and completes; the one-call form when the key is at hand.</summary>
    public byte[] SignWith(ISigningKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return Complete(Input == SigningInput.Digest ? key.SignDigest(_pending.Digest, Spec) : key.Sign(_pending.Digest, Spec));
    }

    /// <summary>The async form of <see cref="SignWith"/>.</summary>
    public async ValueTask<byte[]> SignWithAsync(ISigningKey key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        byte[] sig = Input == SigningInput.Digest
            ? await key.SignDigestAsync(_pending.Digest, Spec, cancellationToken).ConfigureAwait(false)
            : await key.SignAsync(_pending.Digest, Spec, cancellationToken).ConfigureAwait(false);
        return Complete(sig);
    }

    /// <summary>The serialised state (see the remarks on the type).</summary>
    public byte[] Encode() => DerWriter.Sequence(
        DerWriter.SignedInteger(FormatVersion),
        DerWriter.Utf8String(Purpose),
        DerWriter.OctetString(_pending.Key.ToArray(canonical: true)),
        DerWriter.SignedInteger((byte)_pending.Type),
        DerWriter.SignedInteger((byte)_pending.Hash),
        DerWriter.OctetString(_pending.SignedHeader),
        DerWriter.OctetString(_pending.UnhashedRaw),
        DerWriter.OctetString(_pending.Salt),
        DerWriter.OctetString(_pending.Digest));

    /// <summary>Reads a serialised state.</summary>
    /// <exception cref="FormatException">The octets are not a state this library version understands.</exception>
    public static PgpPreparedSignature Decode(ReadOnlySpan<byte> encoded) =>
        TryDecode(encoded, out PgpPreparedSignature? p, out string? error) ? p! : throw new FormatException(error);

    /// <summary>Reads a serialised state, returning false and the reason instead of throwing.</summary>
    public static bool TryDecode(ReadOnlySpan<byte> encoded, out PgpPreparedSignature? state, out string? error)
    {
        state = null;
        error = null;
        try
        {
            var r = new Asn1Reader(encoded, Asn1Rules.Der);
            Asn1Reader s = r.ReadSequence();
            r.ThrowIfNotEmpty();
            int version = s.ReadInt32();
            if (version != FormatVersion)
            {
                error = $"The prepared signature is format version {version}; this library reads version {FormatVersion}.";
                return false;
            }

            if (s.ReadCharacterString(12) != Purpose)
            {
                error = "The state is not a prepared OpenPGP signature.";
                return false;
            }

            Packet kpPacket = Packet.Parse(s.ReadOctetStringBytes());
            int type = s.ReadInt32();
            int hash = s.ReadInt32();
            byte[] header = s.ReadOctetStringBytes();
            byte[] unhashed = s.ReadOctetStringBytes();
            byte[] salt = s.ReadOctetStringBytes();
            byte[] digest = s.ReadOctetStringBytes();
            s.ThrowIfNotEmpty();
            if (kpPacket is not KeyPacket key || key.Version is not (4 or 6) || header.Length < 6 || digest.Length < 2 || header[0] != key.Version || type is < 0 or > 255 || hash is < 0 or > 255
                || header[1] != type || header[2] != (byte)key.Algorithm || header[3] != hash || (key.Version == 6) != (salt.Length > 0))
            {
                error = "The prepared signature's parts do not fit each other.";
                return false;
            }

            state = new PgpPreparedSignature(new PendingSignature(key, key.Version, (SignatureType)type, (PgpHashAlgorithm)hash, header, unhashed, salt, digest));
            return true;
        }
        catch (Exception e) when (e is Asn1ParseException or OpenPgpParseException or PgpException or ArgumentException or InvalidOperationException)
        {
            error = "The prepared signature is damaged: " + e.Message;
            return false;
        }
    }
}
