using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace RecursiveAI.OneCrypto;

/// <summary>A <c>RecipientInfo</c> (RFC 5652 §6.2): how one recipient gets the content-encryption key. Kept as received.</summary>
public abstract class RecipientInfo
{
    private protected RecipientInfo(int version, ReadOnlyMemory<byte> encoded)
    {
        Version = version;
        Encoded = encoded;
    }

    /// <summary>The structure's CMS version.</summary>
    public int Version { get; }

    /// <summary>The whole RecipientInfo choice element as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    internal static RecipientInfo Read(ref Asn1Reader r, ReadOnlyMemory<byte> root, CmsLimits limits)
    {
        Asn1Tag tag = r.PeekTag();
        ReadOnlySpan<byte> whole = r.ReadEncodedValue();
        ReadOnlyMemory<byte> encoded = CmsRead.Slice(root, whole);
        var rd = new Asn1Reader(whole, Asn1Rules.Ber, limits.Asn1);
        if (tag == new Asn1Tag(Asn1Tags.Sequence, true))
        {
            return KeyTransRecipientInfo.Read(rd.ReadSequence(), root, encoded);
        }

        if (tag == Asn1Tag.Context(1))
        {
            return KeyAgreeRecipientInfo.Read(rd.ReadSequence(Asn1Tag.Context(1, true)), root, encoded);
        }

        if (tag == Asn1Tag.Context(2))
        {
            return KekRecipientInfo.Read(rd.ReadSequence(Asn1Tag.Context(2, true)), root, encoded);
        }

        if (tag == Asn1Tag.Context(3))
        {
            return PasswordRecipientInfo.Read(rd.ReadSequence(Asn1Tag.Context(3, true)), root, encoded);
        }

        if (tag == Asn1Tag.Context(4))
        {
            Asn1Reader ori = rd.ReadSequence(Asn1Tag.Context(4, true));
            string type = ori.ReadObjectIdentifier();
            ReadOnlySpan<byte> value = ori.ReadEncodedValue();
            ori.ThrowIfNotEmpty();
            ReadOnlyMemory<byte> valueMem = CmsRead.Slice(root, value);
            if (type == CmsOids.OriKem)
            {
                try
                {
                    return KemRecipientInfo.Read(valueMem, type, encoded, limits);
                }
                catch (Exception e) when (e is Asn1ParseException or CmsParseException or X509ParseException)
                {
                    // A KEMRecipientInfo we cannot read stays available as the raw OtherRecipientInfo.
                }
            }

            return new OtherRecipientInfo(type, valueMem, encoded);
        }

        throw CmsRead.Bad("RecipientInfo", "unknown RecipientInfo choice");
    }

    internal static ReadOnlyMemory<byte> Octets(ref Asn1Reader r, ReadOnlyMemory<byte> root) => SignerInfo.ReadOctets(ref r, root);
}

/// <summary>KeyTransRecipientInfo (RFC 5652 §6.2.1): the content-encryption key encrypted to the recipient's RSA key.</summary>
public sealed class KeyTransRecipientInfo : RecipientInfo
{
    internal KeyTransRecipientInfo(int version, CmsIdentifier id, AlgorithmIdentifier alg, ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> encoded)
        : base(version, encoded)
    {
        Identifier = id;
        KeyEncryptionAlgorithm = alg;
        EncryptedKey = key;
    }

    /// <summary>Names the recipient's certificate.</summary>
    public CmsIdentifier Identifier { get; }

    /// <summary>rsaEncryption (PKCS #1 v1.5) or id-RSAES-OAEP with its parameters.</summary>
    public AlgorithmIdentifier KeyEncryptionAlgorithm { get; }

    /// <summary>The encrypted key octets.</summary>
    public ReadOnlyMemory<byte> EncryptedKey { get; }

    internal static KeyTransRecipientInfo Read(Asn1Reader s, ReadOnlyMemory<byte> root, ReadOnlyMemory<byte> encoded)
    {
        int version = s.ReadInt32();
        CmsIdentifier id = CmsIdentifier.Read(ref s, root);
        AlgorithmIdentifier alg = CmsRead.Alg(ref s, root);
        ReadOnlyMemory<byte> key = Octets(ref s, root);
        s.ThrowIfNotEmpty();
        return new KeyTransRecipientInfo(version, id, alg, key, encoded);
    }
}

/// <summary>One recipient's share of a KeyAgreeRecipientInfo: who it is and the content-encryption key wrapped for them.</summary>
/// <param name="Identifier">Names the recipient's certificate.</param>
/// <param name="EncryptedKey">The wrapped key.</param>
public sealed record RecipientEncryptedKey(CmsIdentifier Identifier, ReadOnlyMemory<byte> EncryptedKey);

/// <summary>KeyAgreeRecipientInfo (RFC 5652 §6.2.2, RFC 5753, RFC 8418): the originator's key and one wrapped key per recipient.</summary>
public sealed class KeyAgreeRecipientInfo : RecipientInfo
{
    internal KeyAgreeRecipientInfo(int version, CmsIdentifier? originatorId, PublicKeyInfo? originatorKey, ReadOnlyMemory<byte> ukm, AlgorithmIdentifier alg, IReadOnlyList<RecipientEncryptedKey> keys, ReadOnlyMemory<byte> encoded)
        : base(version, encoded)
    {
        OriginatorIdentifier = originatorId;
        OriginatorKey = originatorKey;
        Ukm = ukm;
        KeyEncryptionAlgorithm = alg;
        RecipientEncryptedKeys = keys;
    }

    /// <summary>The originator named by certificate, or null when it sent an ephemeral key.</summary>
    public CmsIdentifier? OriginatorIdentifier { get; }

    /// <summary>The originator's ephemeral public key as a <c>SubjectPublicKeyInfo</c>, or null.</summary>
    public PublicKeyInfo? OriginatorKey { get; }

    /// <summary>The user keying material (empty when absent).</summary>
    public ReadOnlyMemory<byte> Ukm { get; }

    /// <summary>The key-agreement scheme; its parameters are the key-wrap algorithm.</summary>
    public AlgorithmIdentifier KeyEncryptionAlgorithm { get; }

    /// <summary>The wrapped keys, one per recipient.</summary>
    public IReadOnlyList<RecipientEncryptedKey> RecipientEncryptedKeys { get; }

    internal static KeyAgreeRecipientInfo Read(Asn1Reader s, ReadOnlyMemory<byte> root, ReadOnlyMemory<byte> encoded)
    {
        int version = s.ReadInt32();
        Asn1Reader orig = s.ReadSequence(Asn1Tag.Context(0, true));
        CmsIdentifier? oid = null;
        PublicKeyInfo? okey = null;
        Asn1Tag t = orig.PeekTag();
        if (t == new Asn1Tag(Asn1Tags.Sequence, true) || t == Asn1Tag.Context(0))
        {
            oid = CmsIdentifier.Read(ref orig, root);
        }
        else if (t == Asn1Tag.Context(1))
        {
            // [1] IMPLICIT OriginatorPublicKey ::= SEQUENCE { algorithm, publicKey BIT STRING }: the same layout as a SubjectPublicKeyInfo.
            byte[] spki = orig.ReadEncodedValue().ToArray();
            spki[0] = 0x30;
            okey = PublicKeyInfo.TryParse(spki, out PublicKeyInfo? k) ? k : null;
        }
        else
        {
            throw CmsRead.Bad("KeyAgreeRecipientInfo", "unknown originator choice");
        }

        orig.ThrowIfNotEmpty();
        ReadOnlyMemory<byte> ukm = default;
        if (s.HasData && s.PeekTag() == Asn1Tag.Context(1))
        {
            Asn1Reader u = s.ReadSequence(Asn1Tag.Context(1, true));
            ukm = Octets(ref u, root);
        }

        AlgorithmIdentifier alg = CmsRead.Alg(ref s, root);
        Asn1Reader list = s.ReadSequence();
        var keys = new List<RecipientEncryptedKey>();
        while (list.HasData)
        {
            Asn1Reader rek = list.ReadSequence();
            CmsIdentifier rid;
            if (rek.PeekTag() == Asn1Tag.Context(0))
            {
                // RecipientKeyIdentifier ::= SEQUENCE { subjectKeyIdentifier, date OPTIONAL, other OPTIONAL } under an implicit [0].
                ReadOnlySpan<byte> whole = rek.ReadEncodedValue();
                var inner = new Asn1Reader(whole, Asn1Rules.Ber);
                Asn1Reader rk = inner.ReadSequence(Asn1Tag.Context(0, true));
                ReadOnlySpan<byte> ski = rk.ReadOctetString();
                rid = new CmsIdentifier(CmsIdentifierKind.SubjectKeyIdentifier, default, default, CmsRead.Slice(root, ski), CmsRead.Slice(root, whole));
            }
            else
            {
                rid = CmsIdentifier.Read(ref rek, root);
            }

            keys.Add(new RecipientEncryptedKey(rid, Octets(ref rek, root)));
            rek.ThrowIfNotEmpty();
            if (keys.Count > 1024)
            {
                throw CmsRead.Limit("KeyAgreeRecipientInfo", "too many recipient keys");
            }
        }

        s.ThrowIfNotEmpty();
        return new KeyAgreeRecipientInfo(version, oid, okey, ukm, alg, keys, encoded);
    }
}

/// <summary>KEKRecipientInfo (RFC 5652 §6.2.3): the key wrapped by a symmetric key the parties share.</summary>
public sealed class KekRecipientInfo : RecipientInfo
{
    internal KekRecipientInfo(int version, ReadOnlyMemory<byte> keyId, AlgorithmIdentifier alg, ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> encoded)
        : base(version, encoded)
    {
        KeyIdentifier = keyId;
        KeyEncryptionAlgorithm = alg;
        EncryptedKey = key;
    }

    /// <summary>The identifier of the shared key.</summary>
    public ReadOnlyMemory<byte> KeyIdentifier { get; }

    /// <summary>The key-wrap algorithm (AES key wrap).</summary>
    public AlgorithmIdentifier KeyEncryptionAlgorithm { get; }

    /// <summary>The wrapped key.</summary>
    public ReadOnlyMemory<byte> EncryptedKey { get; }

    internal static KekRecipientInfo Read(Asn1Reader s, ReadOnlyMemory<byte> root, ReadOnlyMemory<byte> encoded)
    {
        int version = s.ReadInt32();
        Asn1Reader kekid = s.ReadSequence();
        ReadOnlyMemory<byte> id = Octets(ref kekid, root);
        AlgorithmIdentifier alg = CmsRead.Alg(ref s, root);
        ReadOnlyMemory<byte> key = Octets(ref s, root);
        s.ThrowIfNotEmpty();
        return new KekRecipientInfo(version, id, alg, key, encoded);
    }
}

/// <summary>PasswordRecipientInfo (RFC 5652 §6.2.4, RFC 3211): the key wrapped by a key derived from a password.</summary>
public sealed class PasswordRecipientInfo : RecipientInfo
{
    internal PasswordRecipientInfo(int version, AlgorithmIdentifier? kdf, AlgorithmIdentifier alg, ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> encoded)
        : base(version, encoded)
    {
        KeyDerivationAlgorithm = kdf;
        KeyEncryptionAlgorithm = alg;
        EncryptedKey = key;
    }

    /// <summary>How the key-encryption key is derived (PBKDF2 with its parameters), or null when absent.</summary>
    public AlgorithmIdentifier? KeyDerivationAlgorithm { get; }

    /// <summary>id-alg-PWRI-KEK, whose parameter names the cipher that wraps the key.</summary>
    public AlgorithmIdentifier KeyEncryptionAlgorithm { get; }

    /// <summary>The wrapped key (RFC 3211 §2.3).</summary>
    public ReadOnlyMemory<byte> EncryptedKey { get; }

    internal static PasswordRecipientInfo Read(Asn1Reader s, ReadOnlyMemory<byte> root, ReadOnlyMemory<byte> encoded)
    {
        int version = s.ReadInt32();
        AlgorithmIdentifier? kdf = null;
        if (s.HasData && s.PeekTag() == Asn1Tag.Context(0))
        {
            // [0] IMPLICIT AlgorithmIdentifier: the same SEQUENCE under another tag.
            byte[] alg = s.ReadEncodedValue().ToArray();
            alg[0] = 0x30;
            kdf = AlgorithmIdentifier.Parse(alg);
        }

        AlgorithmIdentifier kea = CmsRead.Alg(ref s, root);
        ReadOnlyMemory<byte> key = Octets(ref s, root);
        s.ThrowIfNotEmpty();
        return new PasswordRecipientInfo(version, kdf, kea, key, encoded);
    }
}

/// <summary>An <c>OtherRecipientInfo</c> (RFC 5652 §6.2.5) of a type the library does not interpret, preserved as received.</summary>
public class OtherRecipientInfo : RecipientInfo
{
    internal OtherRecipientInfo(string type, ReadOnlyMemory<byte> value, ReadOnlyMemory<byte> encoded)
        : base(0, encoded)
    {
        OriType = type;
        OriValue = value;
    }

    /// <summary>The type identifier.</summary>
    public string OriType { get; }

    /// <summary>The value element as received.</summary>
    public ReadOnlyMemory<byte> OriValue { get; }
}

/// <summary>KEMRecipientInfo (RFC 9629): the key wrapped by a KEK derived from a key-encapsulation secret (for example ML-KEM, RFC 9936).</summary>
public sealed class KemRecipientInfo : OtherRecipientInfo
{
    private KemRecipientInfo(string type, ReadOnlyMemory<byte> value, ReadOnlyMemory<byte> encoded, CmsIdentifier id, AlgorithmIdentifier kem, ReadOnlyMemory<byte> ct,
        AlgorithmIdentifier kdf, int kekLength, ReadOnlyMemory<byte> ukm, AlgorithmIdentifier wrap, ReadOnlyMemory<byte> key)
        : base(type, value, encoded)
    {
        Identifier = id;
        Kem = kem;
        KemCiphertext = ct;
        Kdf = kdf;
        KekLength = kekLength;
        Ukm = ukm;
        Wrap = wrap;
        EncryptedKey = key;
    }

    /// <summary>Names the recipient's certificate.</summary>
    public CmsIdentifier Identifier { get; }

    /// <summary>The KEM algorithm (for ML-KEM, its identifier).</summary>
    public AlgorithmIdentifier Kem { get; }

    /// <summary>The encapsulated shared secret.</summary>
    public ReadOnlyMemory<byte> KemCiphertext { get; }

    /// <summary>The key-derivation function.</summary>
    public AlgorithmIdentifier Kdf { get; }

    /// <summary>The length of the key-encryption key in octets.</summary>
    public int KekLength { get; }

    /// <summary>The user keying material (empty when absent).</summary>
    public ReadOnlyMemory<byte> Ukm { get; }

    /// <summary>The key-wrap algorithm.</summary>
    public AlgorithmIdentifier Wrap { get; }

    /// <summary>The wrapped key.</summary>
    public ReadOnlyMemory<byte> EncryptedKey { get; }

    internal static KemRecipientInfo Read(ReadOnlyMemory<byte> value, string type, ReadOnlyMemory<byte> encoded, CmsLimits limits)
    {
        var top = new Asn1Reader(value.Span, Asn1Rules.Ber, limits.Asn1);
        Asn1Reader s = top.ReadSequence();
        top.ThrowIfNotEmpty();
        int version = s.ReadInt32();
        if (version != 0)
        {
            throw CmsRead.Unsupported("KEMRecipientInfo", $"version {version}");
        }

        CmsIdentifier id = CmsIdentifier.Read(ref s, value);
        AlgorithmIdentifier kem = CmsRead.Alg(ref s, value);
        ReadOnlyMemory<byte> ct = Octets(ref s, value);
        AlgorithmIdentifier kdf = CmsRead.Alg(ref s, value);
        int kekLength = s.ReadInt32();
        if (kekLength is < 1 or > 65535)
        {
            throw CmsRead.Bad("KEMRecipientInfo", "kekLength is out of range");
        }

        ReadOnlyMemory<byte> ukm = default;
        if (s.HasData && s.PeekTag() == Asn1Tag.Context(0))
        {
            Asn1Reader u = s.ReadSequence(Asn1Tag.Context(0, true));
            ukm = Octets(ref u, value);
        }

        AlgorithmIdentifier wrap = CmsRead.Alg(ref s, value);
        ReadOnlyMemory<byte> key = Octets(ref s, value);
        s.ThrowIfNotEmpty();
        return new KemRecipientInfo(type, value, encoded, id, kem, ct, kdf, kekLength, ukm, wrap, key);
    }
}
