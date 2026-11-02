// The "other process" of a two-phase signature made through a remote signing service: it reads a serialised prepared state, asks the service to sign
// the digest the state names, and writes the raw signature. It never sees the document and completes nothing.
//   usage: CscSigner <service base URL> <token file> <credential id> <pin> <state file> <signature file>
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.Online.Csc;

if (args.Length != 6)
{
    Console.Error.WriteLine("usage: CscSigner <base url> <token file> <credential id> <pin> <state file> <signature file>");
    return 2;
}

if (!PreparedSignature.TryDecode(File.ReadAllBytes(args[4]), out PreparedSignature? state, out string? error))
{
    Console.Error.WriteLine(error);
    return 3;
}

string token = File.ReadAllText(args[1]).Trim();
using var transport = new HttpTransport();
var client = new CscClient(new Fetcher(transport), new Uri(args[0]), new CscStaticTokenSource(new CscAccessToken(token)));
var options = new CscKeyOptions { AuthDataProvider = (_, _) => ValueTask.FromResult<IReadOnlyList<CscAuthObject>>([new CscAuthObject("PIN", args[3])]) };
CscResult<CscSigningKey> opened = await client.OpenSigningKeyAsync(args[2], options);
if (!opened.IsSuccess)
{
    Console.Error.WriteLine(opened.Reason);
    return 4;
}

using CscSigningKey key = opened.Value!;
if (!key.PublicKey.Equals(state!.PublicKey))
{
    Console.Error.WriteLine("the credential's key is not the key the state was prepared for");
    return 5;
}

try
{
    byte[] signature = await key.SignDigestAsync(state.ToSign, state.Spec);
    File.WriteAllBytes(args[5], signature);
}
catch (CscSigningException ex)
{
    Console.Error.WriteLine(ex.Message);
    return 6;
}

return 0;
