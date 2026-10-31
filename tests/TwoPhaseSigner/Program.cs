// The "other process" of a two-phase signature: reads a serialised prepared state and a private key, signs what the state asks for
// (a digest or the message) and writes the raw signature. It never sees the document, and it does not complete anything.
//   usage: TwoPhaseSigner <rsa|ecdsa|ed25519> <key file> <state file> <signature file>
// rsa and ecdsa read a PKCS #8 private key; ed25519 reads the 32-octet seed.
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Primitives;

if (args.Length != 4)
{
    Console.Error.WriteLine("usage: TwoPhaseSigner <rsa|ecdsa|ed25519> <key file> <state file> <signature file>");
    return 2;
}

byte[] keyBytes = File.ReadAllBytes(args[1]);
if (!PreparedSignature.TryDecode(File.ReadAllBytes(args[2]), out PreparedSignature? state, out string? error))
{
    Console.Error.WriteLine(error);
    return 3;
}

IDisposable? owned = null;
ISigningKey key;
switch (args[0])
{
    case "rsa":
        var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(keyBytes, out _);
        owned = rsa;
        key = PrivateKey.FromRsa(rsa);
        break;
    case "ecdsa":
        var ec = ECDsa.Create();
        ec.ImportPkcs8PrivateKey(keyBytes, out _);
        owned = ec;
        key = PrivateKey.FromECDsa(ec);
        break;
    case "ed25519":
        var ed = Ed25519PrivateKey.FromSeed(keyBytes);
        owned = ed;
        key = PrivateKey.FromEd25519(ed);
        break;
    default:
        Console.Error.WriteLine("unknown key kind");
        return 2;
}

using (owned)
using (key)
{
    byte[] signature = state!.Input == SigningInput.Digest ? key.SignDigest(state.ToSign.Span, state.Spec) : key.Sign(state.ToSign.Span, state.Spec);
    File.WriteAllBytes(args[3], signature);
}

return 0;
