using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Pkcs;
using RecursiveAI.OneCrypto.Wire.Ssh;

namespace RecursiveAI.OneCrypto;

/// <summary>
/// A private key that was loaded from a file, ready to use. Which of <see cref="Signing"/>, <see cref="Decryption"/> and
/// <see cref="Agreement"/> are set follows from the algorithm: RSA gives signing and decryption (one object), P-256/384/521 gives
/// signing and agreement, Ed25519/Ed448 and ML-DSA signing only, X25519/X448 agreement only, ML-KEM decryption only. A key of an
/// algorithm this library has no key object for (DSA, for example) has none of them; <see cref="Info"/> still holds it.
/// </summary>
public sealed class LoadedPrivateKey : IDisposable
{
    private readonly List<IDisposable> _owned;
    private bool _disposed;

    internal LoadedPrivateKey(PrivateKeyInfo info, PublicKeyInfo? publicKey, ISigningKey? signing, IDecryptionKey? decryption, IAgreementKey? agreement, List<IDisposable> owned)
    {
        Info = info;
        PublicKey = publicKey;
        Signing = signing;
        Decryption = decryption;
        Agreement = agreement;
        _owned = owned;
    }

    /// <summary>The key as PKCS#8, in a pinned buffer that is zeroed on <see cref="Dispose"/>. Use it to re-encrypt or export.</summary>
    public PrivateKeyInfo Info { get; }

    /// <summary>The algorithm family.</summary>
    public KeyAlgorithm Algorithm => Info.KeyAlgorithm;

    /// <summary>The matching public key; null when the algorithm has no public-key derivation here (DSA).</summary>
    public PublicKeyInfo? PublicKey { get; }

    /// <summary>The key as a signer; null when the algorithm does not sign.</summary>
    public ISigningKey? Signing { get; }

    /// <summary>The key as a decryptor (RSA, ML-KEM); null otherwise.</summary>
    public IDecryptionKey? Decryption { get; }

    /// <summary>The key as a key-agreement key (ECDH, X25519, X448); null otherwise.</summary>
    public IAgreementKey? Agreement { get; }

    /// <summary>The comment of an OpenSSH private key; null for other containers.</summary>
    public string? Comment { get; internal set; }

    /// <summary>The <c>friendlyName</c> attribute of a PKCS#12 bag; null when absent or for other containers.</summary>
    public string? FriendlyName { get; internal set; }

    /// <summary>For a key from a PKCS#12 file, the certificate whose <c>localKeyId</c> matches; otherwise null.</summary>
    public Certificate? Certificate { get; internal set; }

    /// <summary>For an OpenSSH private key, its public key in the clear; otherwise null.</summary>
    public SshPublicKey? SshPublicKey { get; internal set; }

    /// <summary>Disposes the key objects and zeroes <see cref="Info"/>. Safe to call twice.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (IDisposable d in _owned)
        {
            d.Dispose();
        }

        Info.Dispose();
    }
}

/// <summary>
/// Everything one file held, in typed lists in file order. A list that the file has nothing for is empty. Dispose it to release the
/// private keys it holds.
/// </summary>
public sealed class LoadedItems : IDisposable
{
    internal LoadedItems(
        string format,
        List<Certificate> certificates,
        List<CertificateRevocationList> crls,
        List<CertificateSigningRequest> requests,
        List<OcspResponse> ocsp,
        List<PublicKeyInfo> publicKeys,
        List<LoadedPrivateKey> privateKeys,
        List<SshPublicKey> sshPublicKeys,
        List<SshCertificate> sshCertificates)
    {
        Format = format;
        Certificates = certificates;
        Crls = crls;
        CertificateRequests = requests;
        OcspResponses = ocsp;
        PublicKeys = publicKeys;
        PrivateKeys = privateKeys;
        SshPublicKeys = sshPublicKeys;
        SshCertificates = sshCertificates;
    }

    /// <summary>The container format that was detected, for example <c>PEM</c>, <c>DER</c>, <c>PKCS#12</c>, <c>authorized_keys</c>.</summary>
    public string Format { get; }

    /// <summary>X.509 certificates, from PEM, DER, PKCS#7 certificate bags and PKCS#12 files.</summary>
    public IReadOnlyList<Certificate> Certificates { get; }

    /// <summary>Certificate revocation lists, delta CRLs included.</summary>
    public IReadOnlyList<CertificateRevocationList> Crls { get; }

    /// <summary>PKCS#10 certification requests.</summary>
    public IReadOnlyList<CertificateSigningRequest> CertificateRequests { get; }

    /// <summary>OCSP responses (RFC 6960 <c>OCSPResponse</c>).</summary>
    public IReadOnlyList<OcspResponse> OcspResponses { get; }

    /// <summary>Public keys from <c>SubjectPublicKeyInfo</c> and PKCS#1 <c>RSAPublicKey</c> files.</summary>
    public IReadOnlyList<PublicKeyInfo> PublicKeys { get; }

    /// <summary>Private keys, as usable key objects.</summary>
    public IReadOnlyList<LoadedPrivateKey> PrivateKeys { get; }

    /// <summary>OpenSSH public keys: <c>.pub</c> files, <c>authorized_keys</c> lines, RFC 4716 files.</summary>
    public IReadOnlyList<Wire.Ssh.SshPublicKey> SshPublicKeys { get; }

    /// <summary>OpenSSH certificates (<c>*-cert-v01@openssh.com</c>).</summary>
    public IReadOnlyList<SshCertificate> SshCertificates { get; }

    /// <summary>The total number of items of all kinds.</summary>
    public int Count => Certificates.Count + Crls.Count + CertificateRequests.Count + OcspResponses.Count + PublicKeys.Count + PrivateKeys.Count + SshPublicKeys.Count + SshCertificates.Count;

    /// <summary>Disposes the private keys.</summary>
    public void Dispose()
    {
        foreach (LoadedPrivateKey k in PrivateKeys)
        {
            k.Dispose();
        }
    }
}
