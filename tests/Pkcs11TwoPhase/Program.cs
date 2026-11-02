// The three processes of a two-phase signature whose key is on a PKCS #11 token. The state files are all that travels between them.
//   prepare-cms  <certificate.der> <rsa-pkcs1|rsa-pss|ecdsa|ed25519> <data file> <cms state> <signature state>   hashes the data; never sees the token
//   prepare-pgp  <certificate.pgp> <data file> <state file>                                                    same, for an OpenPGP detached signature
//   sign         <module> <token label> <key label> <signature state> <raw signature file> [spki file]         the token holder: signs what the state asks for, never sees the data
//   complete-cms <cms state> <raw signature file> <output .der>                                                checks the signature against the public key and writes the CMS message
//   complete-pgp <state file> <raw signature file> <output .asc>
// The token PIN is read from the environment variable PKCS11_PIN.
using System.Linq;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Keys.Pkcs11;
using RecursiveAI.OneCrypto.OpenPgp;
using RecursiveAI.OneCrypto.X509;

if (args.Length < 3)
{
    Console.Error.WriteLine("usage: Pkcs11TwoPhase prepare-cms|prepare-pgp|sign|complete-cms|complete-pgp ...");
    return 2;
}

DateTimeOffset now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
try
{
    switch (args[0])
    {
        case "prepare-cms":
            {
                Certificate cert = Certificate.Parse(File.ReadAllBytes(args[1]));
                SignatureSpec spec = args[2] switch
                {
                    "rsa-pkcs1" => SignatureSpec.RsaPkcs1(System.Security.Cryptography.HashAlgorithmName.SHA256),
                    "rsa-pss" => SignatureSpec.RsaPss(System.Security.Cryptography.HashAlgorithmName.SHA256),
                    "ecdsa" => SignatureSpec.Ecdsa(System.Security.Cryptography.HashAlgorithmName.SHA256),
                    _ => SignatureSpec.Ed25519(),
                };
                PreparedSignedData p = SignedData.Prepare(File.ReadAllBytes(args[3]), [new CmsSignerSpec { Certificate = cert, SignatureSpec = spec, SigningTime = now }], now, new SignedDataOptions { Detached = true });
                File.WriteAllBytes(args[4], p.Encode());
                File.WriteAllBytes(args[5], p.Signatures[0].Encode());
                return 0;
            }

        case "prepare-pgp":
            {
                PgpCertificate cert = PgpCertificate.Parse(File.ReadAllBytes(args[1]));
                PgpKey signer = cert.FindSigningKey(now) ?? throw new InvalidOperationException("the certificate has no usable signing key");
                using FileStream data = File.OpenRead(args[2]);
                File.WriteAllBytes(args[3], PgpPreparedSignature.PrepareDetached(signer, data, now).Encode());
                return 0;
            }

        case "sign":
            {
                string pin = Environment.GetEnvironmentVariable("PKCS11_PIN") ?? throw new InvalidOperationException("PKCS11_PIN is not set");
                byte[] state = File.ReadAllBytes(args[4]);
                using Pkcs11Module module = Pkcs11Module.Load(args[1]);
                Pkcs11Slot slot = module.GetSlots().Single(s => s.GetTokenInfo().Label == args[2]);
                using Pkcs11Session session = slot.OpenSession();
                session.Login(pin);
                PublicKeyInfo? pub = args.Length > 6 ? PublicKeyInfo.Parse(File.ReadAllBytes(args[6])) : null;
                using Pkcs11Key key = session.OpenKey(args[3], publicKey: pub);
                var signing = (ISigningKey)key;
                SignatureSpec spec;
                ReadOnlyMemory<byte> toSign;
                SigningInput input;
                if (PreparedSignature.TryDecode(state, out PreparedSignature? ps, out _) && ps is not null)
                {
                    (spec, toSign, input) = (ps.Spec, ps.ToSign, ps.Input);
                }
                else
                {
                    PgpPreparedSignature pp = PgpPreparedSignature.Decode(state);
                    (spec, toSign, input) = (pp.Spec, pp.ToSign, pp.Input);
                }

                File.WriteAllBytes(args[5], input == SigningInput.Digest ? signing.SignDigest(toSign.Span, spec) : signing.Sign(toSign.Span, spec));
                return 0;
            }

        case "complete-cms":
            {
                PreparedSignedData p = PreparedSignedData.Decode(File.ReadAllBytes(args[1]));
                SignedData sd = p.Complete(File.ReadAllBytes(args[2]));
                File.WriteAllBytes(args[3], sd.Encoded.ToArray());
                return 0;
            }

        case "complete-pgp":
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
catch (Exception e) when (e is Pkcs11Exception or PgpException or InvalidOperationException or InvalidSignatureException or FormatException)
{
    Console.Error.WriteLine(e.GetType().Name + ": " + e.Message);
    return 1;
}
