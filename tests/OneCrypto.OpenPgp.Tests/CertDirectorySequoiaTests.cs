using System.Diagnostics;
using RecursiveAI.OneCrypto.OpenPgp.CertD;
using RecursiveAI.OneCrypto.OpenPgp.GnuPG;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>
/// Two-way checks against Sequoia's <c>sq</c> run as a black box on the same certificate directory. They run only when
/// <c>ONECRYPTO_SQ</c> names the <c>sq</c> binary.
/// </summary>
public sealed class CertDirectorySequoiaTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "certd-sq-" + Guid.NewGuid().ToString("N"));
    private static readonly string? Sq = Environment.GetEnvironmentVariable("ONECRYPTO_SQ");

    public CertDirectorySequoiaTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private static IReadOnlyList<TransferableKey> Export() =>
        LegacyKeyring.Read(File.ReadAllBytes(GnuPGHomes.Dir("2.4.8", "main", "export.pgp")));

    private static byte[] Bytes(TransferableKey k)
    {
        using var ms = new MemoryStream();
        k.WriteTo(ms);
        return ms.ToArray();
    }

    private (int Exit, string Output) RunSq(string store, params string[] args)
    {
        var psi = new ProcessStartInfo(Sq!) { RedirectStandardOutput = true, RedirectStandardError = true };
        psi.ArgumentList.Add("--home");
        psi.ArgumentList.Add(Path.Combine(_root, "home"));
        psi.ArgumentList.Add("--cert-store");
        psi.ArgumentList.Add(store);
        foreach (string a in args)
        {
            psi.ArgumentList.Add(a);
        }

        using Process p = Process.Start(psi)!;
        Task<string> err = p.StandardError.ReadToEndAsync();
        string output = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        return (p.ExitCode, output + err.Result);
    }

    private static List<string> Fingerprints(string listing) =>
        System.Text.RegularExpressions.Regex.Matches(listing, "[0-9A-F]{40}").Select(m => m.Value).Distinct().Order().ToList();

    [Fact]
    public void SequoiaListsAndExportsWhatWeWrote()
    {
        Assert.SkipWhen(Sq is null, "ONECRYPTO_SQ not set");
        string store = Path.Combine(_root, "ours");
        var ours = CertDirectory.Open(store);
        IReadOnlyList<TransferableKey> keys = Export();
        foreach (TransferableKey k in keys)
        {
            ours.Insert(k);
        }

        // The reference: the same certificates imported by sq itself. It lists only certificates it finds usable (it has no Brainpool, for
        // one), so what matters is that it lists exactly the same ones for both stores.
        string theirs = Path.Combine(_root, "theirs");
        string all = Path.Combine(_root, "all.pgp");
        File.WriteAllBytes(all, keys.SelectMany(Bytes).ToArray());
        RunSq(theirs, "cert", "import", all);
        (int exit, string list) = RunSq(store, "cert", "list", "--gossip");
        Assert.True(exit == 0, list);
        (_, string reference) = RunSq(theirs, "cert", "list", "--gossip");
        Assert.Equal(Fingerprints(reference), Fingerprints(list));
        Assert.True(Fingerprints(list).Count >= keys.Count - 4, list);

        // sq's export must be the certificate we stored, as far as OpenPGP structure goes.
        string fp = keys[0].Primary.FingerprintHex;
        (exit, string exported) = RunSq(store, "cert", "export", "--cert", fp);
        Assert.True(exit == 0, exported);
    }

    [Fact]
    public void SequoiaMergesAnUpdateIntoAStoreWeWroteAndWeReadTheResult()
    {
        Assert.SkipWhen(Sq is null, "ONECRYPTO_SQ not set");
        string store = Path.Combine(_root, "update");
        TransferableKey full = Export()[0];

        // Store only the primary key and its user ID with that ID's signature; the subkey is missing.
        TransferableKey partial = TransferableKey.Parse(full.Packets.Where(p => !(p == full.Subkeys[0].Key || full.Subkeys[0].Signatures.Contains(p))).ToList());
        CertDirectory.Open(store).Insert(partial);

        string file = Path.Combine(_root, "full.pgp");
        File.WriteAllBytes(file, Bytes(full));
        (int exit, string output) = RunSq(store, "cert", "import", file);
        Assert.True(exit == 0, output);

        TransferableKey merged = CertDirectory.Open(store, create: false).Get(full.Primary.FingerprintHex.ToLowerInvariant())!.ReadKey();
        Assert.Single(merged.Subkeys);
        Assert.Equal(full.Subkeys[0].Key.FingerprintHex, merged.Subkeys[0].Key.FingerprintHex);
    }

    [Fact]
    public void WeMergeIntoACertificateSequoiaStoredAndLeaveItsBytesAlone()
    {
        Assert.SkipWhen(Sq is null, "ONECRYPTO_SQ not set");
        string store = Path.Combine(_root, "theirs");
        TransferableKey full = Export()[0];
        string file = Path.Combine(_root, "full.pgp");
        File.WriteAllBytes(file, Bytes(full));
        (int exit, string output) = RunSq(store, "cert", "import", file);
        Assert.True(exit == 0, output);

        var ours = CertDirectory.Open(store, create: false);
        string name = full.Primary.FingerprintHex.ToLowerInvariant();
        CertEntry before = ours.Get(name)!;
        CertEntry after = ours.Insert(full);
        Assert.Equal(before.Tag, after.Tag);
        Assert.Equal(before.Data.ToArray(), after.Data.ToArray());
    }

    [Fact]
    public void SequoiaWaitsForTheWriteLockWeHold()
    {
        Assert.SkipWhen(Sq is null, "ONECRYPTO_SQ not set");
        string store = Path.Combine(_root, "locked");
        TransferableKey k = Export()[0];
        var ours = CertDirectory.Open(store);
        string file = Path.Combine(_root, "k.pgp");
        File.WriteAllBytes(file, Bytes(k));

        Task<(int Exit, string Output)> sq;
        using (var held = new FileStream(Path.Combine(store, "writelock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
        {
            sq = Task.Run(() => RunSq(store, "cert", "import", file));
            Thread.Sleep(3000);
            Assert.False(sq.IsCompleted, "sq wrote while we held the write lock");
            Assert.Null(ours.Get(k.Primary.FingerprintHex.ToLowerInvariant()));
        }

        Assert.True(sq.Wait(TimeSpan.FromSeconds(60)));
        Assert.True(sq.Result.Exit == 0, sq.Result.Output);
        Assert.NotNull(ours.Get(k.Primary.FingerprintHex.ToLowerInvariant()));
    }
}
