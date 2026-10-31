using System.Linq;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Fuzz;

/// <summary>
/// The serialised two-phase signing state. Whatever decodes must encode back to the same octets, and checking arbitrary signatures against it
/// must come back with a result, never an exception. Only the typed refusals of <c>TryDecode</c> may happen on damaged input.
/// </summary>
internal static class KeysTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        RunSignedData(data);
        RunSignature(data);
    }

    /// <summary>The CMS two-phase state: the same promises, plus that completing with arbitrary signatures only ever raises the typed refusal.</summary>
    private static void RunSignedData(ReadOnlySpan<byte> data)
    {
        if (!PreparedSignedData.TryDecode(data, out PreparedSignedData? state, out string? error))
        {
            if (string.IsNullOrEmpty(error))
            {
                throw new InvalidOperationException("TryDecode refused without a reason");
            }

            return;
        }

        if (!state!.Encode().AsSpan().SequenceEqual(data))
        {
            throw new InvalidOperationException("a decoded CMS state did not re-encode to its input");
        }

        byte[] cut = data[..Math.Min(data.Length, 70)].ToArray();
        byte[][] junk = [.. state.Signatures.Select(_ => cut)];
        try
        {
            _ = state.Complete(junk);
        }
        catch (InvalidSignatureException)
        {
            // The expected answer for a signature that does not verify.
        }
        catch (InvalidOperationException)
        {
            // An attached message whose content was prepared from a stream cannot complete in one piece.
        }
    }

    private static void RunSignature(ReadOnlySpan<byte> data)
    {
        if (!PreparedSignature.TryDecode(data, out PreparedSignature? state, out string? error))
        {
            if (string.IsNullOrEmpty(error))
            {
                throw new InvalidOperationException("TryDecode refused without a reason");
            }

            return;
        }

        if (!state!.Encode().AsSpan().SequenceEqual(data))
        {
            throw new InvalidOperationException("a decoded state did not re-encode to its input");
        }

        // A signature cut from the input itself, and an empty one.
        _ = state.Verify(data[..Math.Min(data.Length, 128)]);
        _ = state.Verify([]);
        _ = state.TryComplete(data[^Math.Min(data.Length, 64)..], out _, out _);
    }

    public static IEnumerable<byte[]> Seeds()
    {
        DateTimeOffset at = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
        using var rsa = RSA.Create(2048);
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ISigningKey rk = PrivateKey.FromRsa(rsa);
        using ISigningKey ek = PrivateKey.FromECDsa(ec);
        byte[] doc = "seed document"u8.ToArray();
        yield return PreparedSignature.Prepare(rk.PublicKey, SignatureSpec.RsaPss(HashAlgorithmName.SHA256), doc, CryptoPolicy.Standard, at).Encode();
        yield return PreparedSignature.Prepare(ek.PublicKey, SignatureSpec.Ecdsa(HashAlgorithmName.SHA256, EcdsaSignatureFormat.Rfc4754), doc, CryptoPolicy.Standard, at).Encode();
        yield return PreparedSignature.PrepareDigest(rk.PublicKey, SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256), SHA256.HashData(doc), CryptoPolicy.Standard, at, "x509.crl").Encode();
        using Ed25519Holder ed = Ed25519Holder.Create();
        yield return PreparedSignature.Prepare(ed.Key.PublicKey, SignatureSpec.Ed25519(), doc, CryptoPolicy.Standard, at).Encode();

        // CMS two-phase states: attached from memory, detached, and from a stream.
        var cert = CertificateBuilder.CreateSelfSigned(
            new CertificateOptions { Subject = DistinguishedName.FromString("CN=seed"), NotBefore = at, NotAfter = at.AddDays(30) }, X509Signer.FromKey(ek));
        var spec = new CmsSignerSpec { Certificate = cert, SignatureSpec = SignatureSpec.Ecdsa(HashAlgorithmName.SHA256), SigningTime = at };
        yield return SignedData.Prepare(doc, [spec], at).Encode();
        yield return SignedData.Prepare(doc, [spec], at, new SignedDataOptions { Detached = true }).Encode();
        yield return SignedData.PrepareStream(new MemoryStream(doc), [spec], at).Encode();
    }

    private sealed class Ed25519Holder : IDisposable
    {
        private readonly RecursiveAI.OneCrypto.Primitives.Ed25519PrivateKey _raw;

        private Ed25519Holder(RecursiveAI.OneCrypto.Primitives.Ed25519PrivateKey raw)
        {
            _raw = raw;
            Key = PrivateKey.FromEd25519(raw);
        }

        public ISigningKey Key { get; }

        public static Ed25519Holder Create() => new(RecursiveAI.OneCrypto.Primitives.Ed25519PrivateKey.Generate());

        public void Dispose()
        {
            Key.Dispose();
            _raw.Dispose();
        }
    }
}
