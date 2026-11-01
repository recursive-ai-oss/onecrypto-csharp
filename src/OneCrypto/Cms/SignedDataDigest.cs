using System.Linq;
using System.Security.Cryptography;
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
    /// Like <see cref="DigestAlgorithmFor(CmsSignerSpec, CryptoPolicy?)"/>, as the platform's hash name instead of an OID, for callers that hash with
    /// <see cref="IncrementalHash"/> or pass a <see cref="HashAlgorithmName"/> on (SHAKE256 comes back as <see cref="DigestNames.Shake256"/>).
    /// </summary>
    /// <param name="signer">The signer; needs a certificate and a key, a signer delegate or a signature spec.</param>
    /// <param name="policy">The policy that judges the new signature; default <see cref="CryptoPolicy.Standard"/>.</param>
    /// <returns>The hash name.</returns>
    /// <exception cref="PolicyViolationException">The policy refuses the signer's algorithm or key.</exception>
    public static HashAlgorithmName HashAlgorithmFor(CmsSignerSpec signer, CryptoPolicy? policy = null) =>
        DigestNames.GetHashAlgorithmName(DigestAlgorithmFor(signer, policy));

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
    /// <exception cref="DigestMismatchException">A signer uses another digest algorithm, or the digest has the wrong length.</exception>
    /// <exception cref="InvalidOperationException">A signer has no key: see <see cref="PrepareDetachedFromDigest(ReadOnlySpan{byte}, string, IReadOnlyList{CmsSignerSpec}, DateTimeOffset, SignedDataOptions?)"/>.</exception>
    /// <exception cref="NotSupportedException">A signer has no signed attributes: a signature over bare content cannot be made from a digest.</exception>
    public static SignedData CreateDetachedFromDigest(ReadOnlySpan<byte> contentDigest, string digestAlgorithm, IReadOnlyList<CmsSignerSpec> signers, SignedDataOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(signers);
        if (signers.FirstOrDefault(static s => !s.HasSigner) is not null)
        {
            throw new InvalidOperationException("A signer has no Key or Signer, so this call cannot produce its signature. When the key is elsewhere (a token, a remote service, another process), use SignedData.PrepareDetachedFromDigest with a SignatureSpec, sign PreparedSignedData.ToSign there, and finish with PreparedSignedData.Complete.");
        }

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
    /// Like <see cref="CreateDetachedFromDigest(ReadOnlySpan{byte}, string, IReadOnlyList{CmsSignerSpec}, SignedDataOptions?)"/>, naming the digest algorithm as a
    /// <see cref="HashAlgorithmName"/>, the way PDF and hashing code usually has it.
    /// </summary>
    /// <param name="contentDigest">The digest of the content.</param>
    /// <param name="digestAlgorithm">The hash the digest was made with; see <see cref="DigestNames"/> for the names that map.</param>
    /// <param name="signers">One or more signers with a key or a signer delegate; each must use signed attributes.</param>
    /// <param name="options">Choices (extra certificates, CRLs, policy); the message is always detached.</param>
    /// <returns>The message (definite-length DER).</returns>
    /// <exception cref="DigestMismatchException">A signer uses another digest algorithm, or the digest has the wrong length for the named hash.</exception>
    /// <exception cref="NotSupportedException">The hash has no digest OID, or a signer has no signed attributes.</exception>
    /// <exception cref="InvalidOperationException">A signer has no key (use <see cref="PrepareDetachedFromDigest(ReadOnlySpan{byte}, HashAlgorithmName, IReadOnlyList{CmsSignerSpec}, DateTimeOffset, SignedDataOptions?)"/> for a signature made elsewhere).</exception>
    public static SignedData CreateDetachedFromDigest(ReadOnlySpan<byte> contentDigest, HashAlgorithmName digestAlgorithm, IReadOnlyList<CmsSignerSpec> signers, SignedDataOptions? options = null) =>
        CreateDetachedFromDigest(contentDigest, DigestNames.GetOid(digestAlgorithm), signers, options);

    /// <summary>
    /// Like <see cref="PrepareDetachedFromDigest(ReadOnlySpan{byte}, string, IReadOnlyList{CmsSignerSpec}, DateTimeOffset, SignedDataOptions?)"/>, naming the digest algorithm as a
    /// <see cref="HashAlgorithmName"/>.
    /// </summary>
    /// <param name="contentDigest">The digest of the content.</param>
    /// <param name="digestAlgorithm">The hash the digest was made with.</param>
    /// <param name="signers">One or more signers; the keys are not used here, a <see cref="CmsSignerSpec.SignatureSpec"/> will do.</param>
    /// <param name="at">The moment of signing, for the policy and the state.</param>
    /// <param name="options">Choices; the message is always detached.</param>
    /// <returns>The prepared state.</returns>
    /// <exception cref="DigestMismatchException">A signer uses another digest algorithm, or the digest has the wrong length for the named hash.</exception>
    /// <exception cref="NotSupportedException">The hash has no digest OID.</exception>
    public static PreparedSignedData PrepareDetachedFromDigest(ReadOnlySpan<byte> contentDigest, HashAlgorithmName digestAlgorithm, IReadOnlyList<CmsSignerSpec> signers, DateTimeOffset at, SignedDataOptions? options = null) =>
        PrepareDetachedFromDigest(contentDigest, DigestNames.GetOid(digestAlgorithm), signers, at, options);

    /// <summary>
    /// Phase one of a two-step signature over content that is already hashed (see <see cref="CreateDetachedFromDigest(ReadOnlySpan{byte}, string, IReadOnlyList{CmsSignerSpec}, SignedDataOptions?)"/>). The state serialises
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
            throw new DigestMismatchException(
                $"The digest algorithm is {AlgorithmNames.Describe(digestAlgorithm)}, whose digests are {empty.Length} bytes, but the digest given is {digest.Length} bytes. Hash the content with the algorithm you name (SignedData.DigestAlgorithmFor says which one the signer uses).",
                $"{AlgorithmNames.Describe(digestAlgorithm)} ({empty.Length} bytes)",
                $"{digest.Length} bytes",
                nameof(digest));
        }

        List<SignerPlan> plans = [.. signers.Select(s => SignerPlan.For(s, options.Policy))];
        foreach (SignerPlan p in plans)
        {
            if (p.DigestOid != digestAlgorithm)
            {
                throw new DigestMismatchException(
                    $"A signer uses {AlgorithmNames.Describe(p.DigestOid)}, but the digest was declared as {AlgorithmNames.Describe(digestAlgorithm)}. Hash with SignedData.DigestAlgorithmFor (or HashAlgorithmFor) and pass that algorithm.",
                    AlgorithmNames.Describe(p.DigestOid),
                    AlgorithmNames.Describe(digestAlgorithm),
                    nameof(signers));
            }
        }

        return plans;
    }
}
