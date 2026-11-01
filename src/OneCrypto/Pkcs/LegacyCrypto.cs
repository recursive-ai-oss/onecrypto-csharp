using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Internal;

namespace RecursiveAI.OneCrypto.Pkcs;

/// <summary>
/// The weak algorithms that old key containers use and that this library only reads: triple DES and RC2 for PKCS#12 and PEM
/// encryption, MD5 for the traditional PEM key derivation. They are never used to write. All of them are in this one file so the
/// analyzer suppression below covers nothing else.
/// </summary>
#pragma warning disable CA5350, CA5351 // Reading existing files needs these algorithms; nothing here encrypts or hashes new data.
internal static class LegacyCrypto
{
    public static void TripleDesCbcDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data, Span<byte> destination)
    {
        Platform.RequireLegacyCipher("Triple DES");
        using TripleDES t = TripleDES.Create();
        t.SetKey(key);
        t.DecryptCbc(data, iv, destination, PaddingMode.None);
    }

    public static void Rc2CbcDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data, Span<byte> destination)
    {
        Platform.RequireLegacyCipher("RC2");
        using RC2 rc2 = RC2.Create();
        rc2.KeySize = key.Length * 8;
        rc2.EffectiveKeySize = key.Length * 8;
        rc2.SetKey(key);
        rc2.DecryptCbc(data, iv, destination, PaddingMode.None);
    }

    public static byte[] Sha1(ReadOnlySpan<byte> data) => SHA1.HashData(data);

    public static byte[] Md5(ReadOnlySpan<byte> data) => MD5.HashData(data);
}
#pragma warning restore CA5350, CA5351
