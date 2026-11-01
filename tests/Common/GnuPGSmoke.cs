using System.Text;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.OpenPgp.GnuPG;

namespace OneCrypto.Smoke;

/// <summary>Reads a keybox header and an unprotected GnuPG key file (the RFC 8032 section 7.1 test 1 key) and signs with it.</summary>
internal static class GnuPGSmoke
{
    public static bool Run()
    {
        // A keybox of one header blob: length, type 1, version 1, flags (OpenPGP), the "KBXf" magic and two timestamps.
        byte[] header = new byte[32];
        header[3] = 32;
        header[4] = 1;
        header[5] = 1;
        header[7] = 2;
        Encoding.ASCII.GetBytes("KBXf").CopyTo(header, 8);
        Keybox box = Keybox.Parse(header);
        if (box.Header is null || !box.Header.ContainsOpenPgp || box.Blobs.Count != 1)
        {
            return false;
        }

        byte[] seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        byte[] pub = Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        var text = new StringBuilder("(11:private-key(3:ecc(5:curve7:Ed25519)(5:flags5:eddsa)(1:q33:");
        text.Append('@').Append(Encoding.Latin1.GetString(pub)).Append(")(1:d32:").Append(Encoding.Latin1.GetString(seed)).Append(")))");
        GnuPGKeyFile file = GnuPGKeyFile.Parse(Encoding.Latin1.GetBytes(text.ToString()));
        if (file.IsProtected || file.Curve != "Ed25519")
        {
            return false;
        }

        using GnuPGSecretKey secret = file.Unlock(string.Empty);
        using ISigningKey key = secret.ToSigningKey();
        byte[] signature = key.Sign([], SignatureSpec.Ed25519());
        return Convert.ToHexString(signature).StartsWith("E5564300C360AC729086E2CC806E828A", StringComparison.Ordinal);
    }
}
