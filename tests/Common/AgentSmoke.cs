using System.Net.Sockets;
using System.Text;
using RecursiveAI.OneCrypto.Keys.Agents;

namespace OneCrypto.Smoke;

/// <summary>The agent clients against in-process fake agents on a Unix socket: framing, async state machines and socket use under NativeAOT.</summary>
internal static class AgentSmoke
{
    public static async Task<bool> Run()
    {
        // The directory name GnuPG derives from a home path (z-base-32 of a SHA-1 prefix), as gpgconf prints it.
        if (GpgAgent.HomeHash("/tmp/gnupg-example") != "sha4d11e8m1acn9bz8eizk6u")
        {
            return false;
        }

        string dir = Path.Combine(Path.GetTempPath(), "oc-agent-smoke-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        try
        {
            string gpgSock = Path.Combine(dir, "g"), sshSock = Path.Combine(dir, "s");
            using var gl = Listen(gpgSock);
            using var sl = Listen(sshSock);
            Task gpgServer = Task.Run(async () =>
            {
                using Socket c = await gl.AcceptAsync();
                using var s = new NetworkStream(c);
                await s.WriteAsync("OK hello\n"u8.ToArray());
                await ReadByteUntilNewline(s);
                await s.WriteAsync(Encoding.ASCII.GetBytes("S KEYINFO " + new string('A', 40) + " D - - - P - - -\nOK\n"));
            });
            Task sshServer = Task.Run(async () =>
            {
                using Socket c = await sl.AcceptAsync();
                using var s = new NetworkStream(c);
                var head = new byte[4];
                await s.ReadExactlyAsync(head);
                await s.ReadExactlyAsync(new byte[head[3]]);
                await s.WriteAsync(new byte[] { 0, 0, 0, 5, 12, 0, 0, 0, 0 });
            });
            IReadOnlyList<GpgAgentKeyInfo> keys = await new GpgAgentClient(new GpgAgentOptions { SocketPath = gpgSock, ForwardEnvironment = false }).ListKeysAsync();
            IReadOnlyList<SshAgentIdentity> ids = await new SshAgentClient(new SshAgentOptions { SocketPath = sshSock }).ListIdentitiesAsync();
            await Task.WhenAll(gpgServer, sshServer);
            return keys.Count == 1 && keys[0].Protection == GpgAgentKeyProtection.Passphrase && ids.Count == 0;
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static Socket Listen(string path)
    {
        var l = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        l.Bind(new UnixDomainSocketEndPoint(path));
        l.Listen(1);
        return l;
    }

    private static async Task ReadByteUntilNewline(NetworkStream s)
    {
        var one = new byte[1];
        while (await s.ReadAsync(one) == 1 && one[0] != '\n')
        {
        }
    }
}
