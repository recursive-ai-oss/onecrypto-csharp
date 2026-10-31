using RecursiveAI.OneCrypto.Asn1;

namespace RecursiveAI.OneCrypto;

/// <summary>
/// An <c>AlgorithmIdentifier</c> (RFC 5280 §4.1.1.2): an object identifier and optional parameters, kept as the exact octets received.
/// </summary>
public sealed class AlgorithmIdentifier : IEquatable<AlgorithmIdentifier>
{
    private readonly ReadOnlyMemory<byte> _encoded;
    private readonly ReadOnlyMemory<byte> _parameters;

    private AlgorithmIdentifier(string oid, ReadOnlyMemory<byte> encoded, ReadOnlyMemory<byte> parameters)
    {
        Oid = oid;
        _encoded = encoded;
        _parameters = parameters;
    }

    /// <summary>The algorithm's object identifier in dotted form.</summary>
    public string Oid { get; }

    /// <summary>The encoded parameters element (tag, length and value), or empty when the field is absent. An explicit NULL is <c>05 00</c>.</summary>
    public ReadOnlyMemory<byte> Parameters => _parameters;

    /// <summary>The whole <c>AlgorithmIdentifier</c> SEQUENCE exactly as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded => _encoded;

    /// <summary>A readable name for the algorithm when the library knows it, otherwise the dotted identifier.</summary>
    public string Name => AlgorithmNames.Describe(Oid);

    /// <summary>Builds an identifier from an object identifier and an optional encoded parameters element.</summary>
    /// <param name="oid">The dotted identifier.</param>
    /// <param name="parameters">A complete encoded element, or empty for none.</param>
    public static AlgorithmIdentifier Create(string oid, ReadOnlyMemory<byte> parameters = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(oid);
        byte[] o = DerWriter.Oid(oid);
        byte[] enc = parameters.IsEmpty ? DerWriter.Sequence(o) : DerWriter.Sequence(o, parameters.ToArray());
        return new AlgorithmIdentifier(oid, enc, parameters.IsEmpty ? ReadOnlyMemory<byte>.Empty : enc.AsMemory(enc.Length - parameters.Length));
    }

    /// <summary>Builds an identifier whose parameters are an explicit NULL (as for RSA and the SHA-2 hashes).</summary>
    public static AlgorithmIdentifier WithNull(string oid) => Create(oid, new byte[] { 5, 0 });

    /// <summary>Reads an identifier from its encoding.</summary>
    /// <exception cref="X509ParseException">The octets are not an AlgorithmIdentifier.</exception>
    public static AlgorithmIdentifier Parse(ReadOnlyMemory<byte> encoded)
    {
        try
        {
            var r = new Asn1Reader(encoded.Span, Asn1Rules.Ber);
            AlgorithmIdentifier a = Read(ref r, encoded);
            r.ThrowIfNotEmpty();
            return a;
        }
        catch (Asn1ParseException e)
        {
            throw new X509ParseException("AlgorithmIdentifier", e);
        }
    }

    /// <summary>Reads an identifier, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out AlgorithmIdentifier? value)
    {
        try
        {
            value = Parse(encoded);
            return true;
        }
        catch (X509ParseException)
        {
            value = null;
            return false;
        }
    }

    /// <summary>Reads the next element of <paramref name="r"/> (which iterates over <paramref name="root"/>) as an identifier.</summary>
    internal static AlgorithmIdentifier Read(ref Asn1Reader r, ReadOnlyMemory<byte> root)
    {
        ReadOnlySpan<byte> whole = r.ReadEncodedValue();
        var inner = new Asn1Reader(whole, Asn1Rules.Ber, r.Limits);
        Asn1Reader seq = inner.ReadSequence();
        inner.ThrowIfNotEmpty();
        string oid = seq.ReadObjectIdentifier();
        ReadOnlySpan<byte> parameters = default;
        if (seq.HasData)
        {
            parameters = seq.ReadEncodedValue();
            if (seq.HasData)
            {
                throw new X509ParseException("AlgorithmIdentifier", X509Error.UnexpectedStructure, "extra elements after the parameters");
            }
        }

        return new AlgorithmIdentifier(oid, X509Read.Slice(root, whole), X509Read.Slice(root, parameters));
    }

    /// <inheritdoc/>
    public bool Equals(AlgorithmIdentifier? other) => other is not null && _encoded.Span.SequenceEqual(other._encoded.Span);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as AlgorithmIdentifier);

    /// <inheritdoc/>
    public override int GetHashCode() => Oid.GetHashCode(StringComparison.Ordinal);

    /// <inheritdoc/>
    public override string ToString() => Name;
}

/// <summary>Readable names for the identifiers in <see cref="KnownOids"/>.</summary>
internal static class AlgorithmNames
{
    public static string Describe(string oid) => oid switch
    {
        KnownOids.RsaEncryption => "RSA",
        KnownOids.Md5WithRsa => "MD5 with RSA",
        KnownOids.Sha1WithRsa => "SHA-1 with RSA",
        KnownOids.Sha224WithRsa => "SHA-224 with RSA",
        KnownOids.Sha256WithRsa => "SHA-256 with RSA",
        KnownOids.Sha384WithRsa => "SHA-384 with RSA",
        KnownOids.Sha512WithRsa => "SHA-512 with RSA",
        KnownOids.RsaPss => "RSASSA-PSS",
        KnownOids.RsaOaep => "RSAES-OAEP",
        KnownOids.EcPublicKey => "EC",
        KnownOids.EcdsaSha1 => "ECDSA with SHA-1",
        KnownOids.EcdsaSha224 => "ECDSA with SHA-224",
        KnownOids.EcdsaSha256 => "ECDSA with SHA-256",
        KnownOids.EcdsaSha384 => "ECDSA with SHA-384",
        KnownOids.EcdsaSha512 => "ECDSA with SHA-512",
        KnownOids.Ed25519 => "Ed25519",
        KnownOids.Ed448 => "Ed448",
        KnownOids.X25519 => "X25519",
        KnownOids.X448 => "X448",
        KnownOids.MlDsa44 => "ML-DSA-44",
        KnownOids.MlDsa65 => "ML-DSA-65",
        KnownOids.MlDsa87 => "ML-DSA-87",
        KnownOids.MlKem512 => "ML-KEM-512",
        KnownOids.MlKem768 => "ML-KEM-768",
        KnownOids.MlKem1024 => "ML-KEM-1024",
        KnownOids.P256 => "P-256",
        KnownOids.P384 => "P-384",
        KnownOids.P521 => "P-521",
        KnownOids.BrainpoolP256r1 => "brainpoolP256r1",
        KnownOids.BrainpoolP384r1 => "brainpoolP384r1",
        KnownOids.BrainpoolP512r1 => "brainpoolP512r1",
        KnownOids.Sha1 => "SHA-1",
        KnownOids.Sha224 => "SHA-224",
        KnownOids.Sha256 => "SHA-256",
        KnownOids.Sha384 => "SHA-384",
        KnownOids.Sha512 => "SHA-512",
        KnownOids.Sha3256 => "SHA3-256",
        KnownOids.Sha3384 => "SHA3-384",
        KnownOids.Sha3512 => "SHA3-512",
        _ => SlhDsaName(oid) ?? oid,
    };

    /// <summary>FIPS 205 parameter-set names for 2.16.840.1.101.3.4.3.20 to .31 (RFC 9909).</summary>
    public static string? SlhDsaName(string oid)
    {
        const string prefix = "2.16.840.1.101.3.4.3.";
        if (!oid.StartsWith(prefix, StringComparison.Ordinal) || !int.TryParse(oid.AsSpan(prefix.Length), out int n) || n is < 20 or > 31)
        {
            return null;
        }

        string[] names =
        [
            "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
            "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
        ];
        return names[n - 20];
    }
}
