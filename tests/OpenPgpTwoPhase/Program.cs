// The three steps of a two-phase OpenPGP signature, each its own process so the state is all that travels between them.
//   prepare  <certificate> <data file> <state file> [text]       hashes the data and writes the serialised state
//   sign     <secret key file> <state file> <signature file>      the key holder: signs what the state asks for, never sees the data
//   complete <state file> <signature file> <output file>          checks the signature against the public key and writes the OpenPGP signature (armored)
//   usage: OpenPgpTwoPhase <step> ...    (the key may be protected with the password in the environment variable TWO_PHASE_PASSWORD)
using System.Text;
using RecursiveAI.OneCrypto.OpenPgp;

if (args.Length < 4)
{
    Console.Error.WriteLine("usage: OpenPgpTwoPhase prepare|sign|complete ...");
    return 2;
}

DateTimeOffset now = TimeProvider.System.GetUtcNow();
try
{
    return Run(args, now);
}
catch (Exception e) when (e is PgpException or InvalidOperationException or FormatException)
{
    Console.Error.WriteLine(e.Message);
    return 1;
}

static int Run(string[] args, DateTimeOffset now)
{
switch (args[0])
{
    case "prepare":
        {
            PgpCertificate cert = PgpCertificate.Parse(File.ReadAllBytes(args[1]));
            PgpKey signer = cert.FindSigningKey(now) ?? throw new InvalidOperationException("the certificate has no usable signing key");
            using FileStream data = File.OpenRead(args[2]);
            PgpPreparedSignature p = PgpPreparedSignature.PrepareDetached(signer, data, now, text: args.Length > 4 && args[4] == "text");
            File.WriteAllBytes(args[3], p.Encode());
            return 0;
        }

    case "sign":
        {
            PgpCertificate key = PgpCertificate.Parse(File.ReadAllBytes(args[1]));
            PgpPreparedSignature p = PgpPreparedSignature.Decode(File.ReadAllBytes(args[2]));
            PgpKey own = key.FindKey(p.Signer.GetFingerprint()) ?? throw new InvalidOperationException("the key is not the one the signature was prepared for");
            string? pw = Environment.GetEnvironmentVariable("TWO_PHASE_PASSWORD");
            using PgpSecretKey secret = PgpSecretKey.Unlock(own, pw is null ? [] : [Encoding.UTF8.GetBytes(pw)]);
            var spec = p.Spec;
            byte[] raw = p.Input == RecursiveAI.OneCrypto.Keys.SigningInput.Digest ? secret.SigningKey.SignDigest(p.ToSign.Span, spec) : secret.SigningKey.Sign(p.ToSign.Span, spec);
            File.WriteAllBytes(args[3], raw);
            return 0;
        }

    case "complete":
        {
            PgpPreparedSignature p = PgpPreparedSignature.Decode(File.ReadAllBytes(args[1]));
            File.WriteAllBytes(args[3], p.CompleteArmored(File.ReadAllBytes(args[2])));
            return 0;
        }

    default:
        Console.Error.WriteLine("unknown step");
        return 2;
}
}
