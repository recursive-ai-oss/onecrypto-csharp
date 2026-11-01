using System.Linq;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace RecursiveAI.OneCrypto;

public sealed partial class SignedData
{
    /// <summary>
    /// The OID of the digest algorithm a signer will use for the message-digest attribute: the signer's own choice when it names one, else the
    /// hash its signature scheme implies (SHA-512 for Ed25519 and ML-DSA, SHAKE256 with a 512-bit output for Ed448, RFC 8419 §3.1). Callers that
    /// hash content themselves, for example the byte ranges of a PDF, hash with this algorithm.
    /// </summary>
    /// <param name="signer">The signer; needs a certificate and a key, a signer delegate or a signature spec.</param>
    /// <param name="policy">The policy that judges the new signature; default <see cref="CryptoPolicy.Standard"/>.</param>
    /// <returns>The digest algorithm OID.</returns>
    /// <exception cref="PolicyViolationException">The policy refuses the signer's algorithm or key.</exception>
    public static string DigestAlgorithmFor(CmsSignerSpec signer, CryptoPolicy? policy = null) => SignerPlan.For(signer, policy).DigestOid;

    /// <summary>
    /// Hashes the rest of <paramref name="content"/> in constant memory with the digest algorithm <paramref name="digestAlgorithm"/> (an OID,
    /// including SHAKE256 for Ed448), the way the message-digest attribute needs it.
    /// </summary>
    /// <param name="digestAlgorithm">The digest algorithm OID, as returned by <see cref="DigestAlgorithmFor"/>.</param>
    /// <param name="content">The stream to read to its end.</param>
    /// <returns>The digest.</returns>
    /// <exception cref="NotSupportedException">The platform lacks the algorithm.</exception>
    public static byte[] HashContent(string digestAlgorithm, Stream content)
    {
        ArgumentNullException.ThrowIfNull(digestAlgorithm);
        ArgumentNullException.ThrowIfNull(content);
        if (!CmsDigest.TryCreate(digestAlgorithm, out CmsDigest? d))
        {
            throw new NotSupportedException($"The digest algorithm {AlgorithmNames.Describe(digestAlgorithm)} is not available on this platform.");
        }

        using (d)
        {
            byte[] buffer = new byte[CmsStream.Chunk];
            int n;
            while ((n = content.Read(buffer, 0, buffer.Length)) > 0)
            {
                d!.Append(buffer.AsSpan(0, n));
            }

            return d!.Finish();
        }
    }

    /// <summary>
    /// Builds a detached SignedData for content that is already hashed, signing with each signer's key. The signed attributes are the content
    /// type, the message digest, the ESS signing-certificate (v2 unless the spec says otherwise) and whatever the spec adds; the signing time only
    /// when the spec sets one. This is the signing half of PDF and other external-digest flows: the platform's CMS signing class cannot sign a digest.
    /// </summary>
    /// <param name="contentDigest">The digest of the content under <paramref name="digestAlgorithm"/>.</param>
    /// <param name="digestAlgorithm">The digest algorithm OID. It must be the one each signer uses (<see cref="DigestAlgorithmFor"/>).</param>
    /// <param name="signers">One or more signers with a key or a signer delegate; each must use signed attributes.</param>
    /// <param name="options">Choices (extra certificates, CRLs, policy); the message is always detached.</param>
    /// <returns>The message (definite-length DER).</returns>
    /// <exception cref="ArgumentException">A signer uses another digest algorithm, or the digest has the wrong length.</exception>
    /// <exception cref="NotSupportedException">A signer has no signed attributes: a signature over bare content cannot be made from a digest.</exception>
    public static SignedData CreateDetachedFromDigest(ReadOnlySpan<byte> contentDigest, string digestAlgorithm, IReadOnlyList<CmsSignerSpec> signers, SignedDataOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(signers);
        SignedDataOptions o = Detach(options);
        List<SignerPlan> plans = CheckDigest(contentDigest, digestAlgorithm, signers, o);
        byte[] digest = contentDigest.ToArray();
        var infos = new List<byte[]>();
        foreach (SignerPlan p in plans)
        {
            infos.Add(p.Build(o.ContentType, digest, default, countersignature: false));
        }

        return Assemble(o, plans, DerWriter.Sequence(DerWriter.Oid(o.ContentType)), infos);
    }

    /// <summary>
    /// Phase one of a two-step signature over content that is already hashed (see <see cref="CreateDetachedFromDigest"/>). The state serialises
    /// (<see cref="PreparedSignedData.Encode"/>), so phase two may run in another process.
    /// </summary>
    /// <param name="contentDigest">The digest of the content under <paramref name="digestAlgorithm"/>.</param>
    /// <param name="digestAlgorithm">The digest algorithm OID each signer uses.</param>
    /// <param name="signers">One or more signers; the keys are not used here, a <see cref="CmsSignerSpec.SignatureSpec"/> will do.</param>
    /// <param name="at">The moment of signing, for the policy and the state.</param>
    /// <param name="options">Choices; the message is always detached.</param>
    /// <returns>The prepared state; complete it with <see cref="PreparedSignedData.Complete(IReadOnlyList{byte[]})"/>.</returns>
    public static PreparedSignedData PrepareDetachedFromDigest(ReadOnlySpan<byte> contentDigest, string digestAlgorithm, IReadOnlyList<CmsSignerSpec> signers, DateTimeOffset at, SignedDataOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(signers);
        SignedDataOptions o = Detach(options);
        List<SignerPlan> plans = CheckDigest(contentDigest, digestAlgorithm, signers, o);
        var digests = new SortedDictionary<string, byte[]>(StringComparer.Ordinal) { [digestAlgorithm] = contentDigest.ToArray() };
        return PreparedSignedData.Create(plans, o, at, p => digests[p.DigestOid], default, retained: false, digests);
    }

    private static SignedDataOptions Detach(SignedDataOptions? options) => new()
    {
        ContentType = options?.ContentType ?? CmsOids.Data,
        Detached = true,
        Certificates = options?.Certificates ?? [],
        IncludeSignerCertificates = options?.IncludeSignerCertificates ?? true,
        Crls = options?.Crls ?? [],
        Policy = options?.Policy,
    };

    private static List<SignerPlan> CheckDigest(ReadOnlySpan<byte> digest, string digestAlgorithm, IReadOnlyList<CmsSignerSpec> signers, SignedDataOptions options)
    {
        ArgumentNullException.ThrowIfNull(digestAlgorithm);
        if (signers.Count == 0)
        {
            throw new ArgumentException("At least one signer is needed.", nameof(signers));
        }

        if (signers.Any(static s => !s.SignedAttributes))
        {
            throw new NotSupportedException("A signature over a digest needs signed attributes: the bare content is not at hand.");
        }

        if (!CmsDigest.TryHash(digestAlgorithm, [], out byte[] empty))
        {
            throw new NotSupportedException($"The digest algorithm {AlgorithmNames.Describe(digestAlgorithm)} is not available on this platform.");
        }

        if (digest.Length != empty.Length)
        {
            throw new ArgumentException($"A {AlgorithmNames.Describe(digestAlgorithm)} digest is {empty.Length} bytes; got {digest.Length}.", nameof(digest));
        }

        List<SignerPlan> plans = [.. signers.Select(s => SignerPlan.For(s, options.Policy))];
        foreach (SignerPlan p in plans)
        {
            if (p.DigestOid != digestAlgorithm)
            {
                throw new ArgumentException($"A signer uses {AlgorithmNames.Describe(p.DigestOid)}, not {AlgorithmNames.Describe(digestAlgorithm)}; hash with SignedData.DigestAlgorithmFor.", nameof(signers));
            }
        }

        return plans;
    }
}
