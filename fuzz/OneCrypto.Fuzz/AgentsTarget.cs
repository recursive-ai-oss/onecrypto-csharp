using System.Linq;
using System.Text;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Keys.Agents;

namespace OneCrypto.Fuzz;

/// <summary>
/// The agent clients' parsers on hostile replies. The first octet picks the surface: 0 an Assuan conversation (the rest is what the server says after the greeting,
/// read by a key listing, a public-key read and a signature), 1 an S-expression as a public key and as a signature value, 2 an ssh-agent identities reply, 3 an ssh-agent
/// signature reply. Only the agent exceptions may escape.
/// </summary>
internal static class AgentsTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return;
        }

        byte[] rest = data[1..].ToArray();
        try
        {
            switch (data[0] % 4)
            {
                case 0:
                    Assuan(rest);
                    break;
                case 1:
                    SExpressions(rest);
                    break;
                case 2:
                    _ = SshAgentClient.ParseIdentities(rest);
                    break;
                default:
                    SshReply(rest);
                    break;
            }
        }
        catch (AgentException)
        {
        }
        catch (AlgorithmNotSupportedException)
        {
        }
    }

    private static void Assuan(byte[] serverBytes)
    {
        // Three commands read the same stream in turn; the limits are small so that the cut-offs are reached.
        using var session = new AssuanSession(new Duplex(Encoding.ASCII.GetBytes("OK hello\n").Concat(serverBytes).ToArray()), 8192);
        session.ReadGreetingAsync(default).GetAwaiter().GetResult();
        for (int i = 0; i < 3; i++)
        {
            AssuanReply r = session.CommandAsync("KEYINFO --list", (kw, parameters, max) => kw == "TBSDATA" ? [1, 2, 3] : null, default).GetAwaiter().GetResult();
            try
            {
                _ = GpgAgentKey.FromPublicKeySExp(new GpgAgentClient(), new string('A', 40), r.Data, null);
            }
            catch (AgentException)
            {
            }
            catch (AlgorithmNotSupportedException)
            {
            }
        }
    }

    private static void SExpressions(byte[] bytes)
    {
        if (SExp.TryParse(bytes, out SExp? e, out string? error))
        {
            if (e is null || error is not null)
            {
                throw new InvalidOperationException("A parse reported success with an error, or no result.");
            }

            _ = e.Name;
            _ = e.Find("curve");
            _ = e.ValueOf("n");
        }

        _ = GpgAgentKey.FromPublicKeySExp(new GpgAgentClient(), new string('A', 40), bytes, null);
    }

    private static void SshReply(byte[] bytes)
    {
        // A reply of the sign-response type, read with a small message limit; a real signature would need the key, so only the framing is exercised.
        SshAgentClient.ExchangeAsync(new Duplex(bytes), [13], 14, 4096, default).GetAwaiter().GetResult();
    }

    public static IEnumerable<byte[]> Seeds()
    {
        byte[] Prefix(byte kind, byte[] body) => [kind, .. body];
        yield return Prefix(0, "S KEYINFO 1C442502BB0168FE04CD995CE3A4BC5389139914 D - - - C - - -\nOK\nD (10:public-key(3:ecc(5:curve7:Ed25519)(5:flags5:eddsa)(1:q33:@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)))\nOK\nINQUIRE TBSDATA\nD (7:sig-val(5:eddsa(1:r1:a)(1:s1:b)))\nOK\n"u8.ToArray());
        yield return Prefix(0, "# comment\nD %25%0D%0A\nERR 83886179 Operation cancelled <Pinentry>\nS INQUIRE_MAXLEN 2048\nOK done\n"u8.ToArray());
        yield return Prefix(1, "(10:public-key(3:rsa(1:n5:\0abcd)(1:e3:\u0001\0\u0001)))"u8.ToArray());
        yield return Prefix(1, "(10:public-key(3:ecc(5:curve10:NIST P-256)(1:q65:\u0004abcdefghijklmnopqrstuvwxyz012345abcdefghijklmnopqrstuvwxyz012345)))"u8.ToArray());
        yield return Prefix(2, [12, 0, 0, 0, 1, 0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 2, 0x68, 0x69]);
        yield return Prefix(3, [0, 0, 0, 12, 14, 0, 0, 0, 7, 0, 0, 0, 3, 1, 2, 3]);
    }

    /// <summary>A stream that reads from a fixed buffer and swallows writes.</summary>
    private sealed class Duplex(byte[] input) : Stream
    {
        private readonly MemoryStream _in = new(input);

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => _in.Read(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
        }
    }
}
