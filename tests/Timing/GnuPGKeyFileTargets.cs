using System.Text;
using RecursiveAI.OneCrypto.OpenPgp.GnuPG;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Timing;

/// <summary>
/// The glue that turns a GnuPG key file's secret parameters into a key object: reading the secret atom, the byte reversal GnuPG applies to
/// Curve25519 scalars, and building the key. The file is unprotected, so the passphrase key derivation and OCB decryption (which have
/// their own evidence) are not in the timed call; the secret scalar is. Per call the file is parsed in the untimed hook and only
/// <c>Unlock</c> plus the key-object build are timed. Fixed key against fresh random keys, and an A/A control.
/// </summary>
internal static class GnuPGKeyFileTargets
{
    public static IEnumerable<TimingTarget> Targets() =>
    [
        new FileKey("GnuPG-keyfile", "unlock-ed25519", ed: true, control: false),
        new FileKey("GnuPG-keyfile", "unlock-cv25519", ed: false, control: false),
        new FileKey("GnuPG-keyfile", "control-unlock-ed25519", ed: true, control: true),
    ];

    private sealed class FileKey(string primitive, string operation, bool ed, bool control) : TimingTarget
    {
        private readonly byte[] _fixedKey = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        private readonly byte[] _key = new byte[32];
        private TimingClass[] _classes = [];
        private GnuPGKeyFile? _file;
        private GnuPGSecretKey? _secret;
        private int _sink;

        public override string Primitive => primitive;

        public override string Operation => operation;

        public override void Prepare(ReadOnlySpan<TimingClass> classes) => _classes = classes.ToArray();

        public override void Before(int index)
        {
            _secret?.Dispose();
            FillKey(_key, _fixedKey, _classes[index], control);
            byte[] pub = new byte[33];
            pub[0] = 0x40;
            byte[] d = (byte[])_key.Clone();
            if (ed)
            {
                Ed25519.DerivePublicKey(_key, pub.AsSpan(1));
            }
            else
            {
                X25519.DerivePublicKey(_key, pub.AsSpan(1));
                Array.Reverse(d); // GnuPG stores the Curve25519 scalar big-endian
            }

            string curve = ed ? "Ed25519" : "Curve25519";
            string flags = ed ? "eddsa" : "djb-tweak";
            var sb = new StringBuilder();
            sb.Append("(11:private-key(3:ecc(5:curve").Append(curve.Length).Append(':').Append(curve).Append(")(5:flags").Append(flags.Length).Append(':').Append(flags).Append(")(1:q33:");
            sb.Append(Encoding.Latin1.GetString(pub)).Append(")(1:d32:").Append(Encoding.Latin1.GetString(d)).Append(")))");
            _file = GnuPGKeyFile.Parse(Encoding.Latin1.GetBytes(sb.ToString()));
        }

        public override void Run(int index)
        {
            _secret = _file!.Unlock(string.Empty);
            if (ed)
            {
                _sink += _secret.ToSigningKey() is null ? 1 : 0;
            }
            else
            {
                _sink += _secret.ToAgreementKey() is null ? 1 : 0;
            }
        }
    }
}
