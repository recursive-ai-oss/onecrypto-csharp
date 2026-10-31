using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Pkcs;

/// <summary>
/// The platform's ML-DSA and ML-KEM PKCS#8 and SubjectPublicKeyInfo calls, which the platform still marks experimental. This is the only
/// file in the PKCS code that touches them; the public methods that reach them say "preview".
/// </summary>
#pragma warning disable SYSLIB5006 // The platform marks these experimental; kept to this file.
internal static class PqKeys
{
    public static MLDsa ImportMLDsa(ReadOnlySpan<byte> pkcs8) => MLDsa.ImportPkcs8PrivateKey(pkcs8);

    public static MLKem ImportMLKem(ReadOnlySpan<byte> pkcs8) => MLKem.ImportPkcs8PrivateKey(pkcs8);

    public static byte[] SpkiOf(MLDsa k) => k.ExportSubjectPublicKeyInfo();

    public static byte[] SpkiOf(MLKem k) => k.ExportSubjectPublicKeyInfo();

    public static byte[] Pkcs8Of(MLDsa k) => k.ExportPkcs8PrivateKey();

    public static byte[] Pkcs8Of(MLKem k) => k.ExportPkcs8PrivateKey();
}
#pragma warning restore SYSLIB5006
