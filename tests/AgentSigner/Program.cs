// The "other process" of a two-phase signature when the key lives in gpg-agent: reads a serialised prepared state, asks the agent to sign what it names, and writes
// the raw signature. It never sees the document and completes nothing.
//   usage: AgentSigner <core|pgp> <agent socket path> <keygrip> <state file> <signature file>
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Keys.Agents;
using RecursiveAI.OneCrypto.OpenPgp;

if (args.Length != 5)
{
    Console.Error.WriteLine("usage: AgentSigner <core|pgp> <agent socket path> <keygrip> <state file> <signature file>");
    return 2;
}

byte[] state = File.ReadAllBytes(args[3]);
var client = new GpgAgentClient(new GpgAgentOptions { SocketPath = args[1] });
try
{
    using GpgAgentKey key = client.GetKey(args[2]);
    ISigningKey signer = (ISigningKey)key;
    byte[] signature;
    if (args[0] == "core")
    {
        if (!PreparedSignature.TryDecode(state, out PreparedSignature? p, out string? error))
        {
            Console.Error.WriteLine(error);
            return 3;
        }

        signature = p!.SignWith(signer);
    }
    else
    {
        PgpPreparedSignature p = PgpPreparedSignature.Decode(state);
        signature = p.Input == SigningInput.Digest ? signer.SignDigest(p.ToSign.Span, p.Spec) : signer.Sign(p.ToSign.Span, p.Spec);
    }

    File.WriteAllBytes(args[4], signature);
    return 0;
}
catch (AgentException e)
{
    Console.Error.WriteLine(e.GetType().Name + ": " + e.Message);
    return 4;
}
