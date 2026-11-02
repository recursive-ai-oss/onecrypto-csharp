using System.Diagnostics;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Keys.Pkcs11;

namespace OneCrypto.Smoke;

/// <summary>
/// The PKCS #11 backend from the published app: typed errors for a missing module, and, when a SoftHSM2 module and a configuration are named in
/// the environment (ONECRYPTO_SOFTHSM2_MODULE, ONECRYPTO_SOFTHSM2_UTIL, SOFTHSM2_CONF), keys made and used on a token.
/// </summary>
internal static class Pkcs11Smoke
{
    public static bool Run()
    {
        try
        {
            _ = Pkcs11Module.Load("/nonexistent/pkcs11-module.so");
            return false;
        }
        catch (Pkcs11ModuleException)
        {
        }

        string? module = Environment.GetEnvironmentVariable("ONECRYPTO_SOFTHSM2_MODULE");
        string? util = Environment.GetEnvironmentVariable("ONECRYPTO_SOFTHSM2_UTIL");
        if (module is null || util is null || Environment.GetEnvironmentVariable("SOFTHSM2_CONF") is null)
        {
            Console.WriteLine("pkcs11 smoke: no SoftHSM2 in the environment, the token part is skipped");
            return true;
        }

        var psi = new ProcessStartInfo(util) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string a in new[] { "--init-token", "--free", "--label", "smoke", "--so-pin", "12345678", "--pin", "4711", "--module", module })
        {
            psi.ArgumentList.Add(a);
        }

        using (Process p = Process.Start(psi)!)
        {
            p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit();
            if (p.ExitCode != 0)
            {
                return false;
            }
        }

        using Pkcs11Module m = Pkcs11Module.Load(module);
        Pkcs11Slot slot = m.GetSlots().First(s => s.GetTokenInfo().Label == "smoke");
        using Pkcs11Session session = slot.OpenSession(readWrite: true);
        try
        {
            session.Login("0000");
            return false;
        }
        catch (Pkcs11PinException)
        {
        }

        session.Login("4711");
        byte[] message = "smoke"u8.ToArray();

        Pkcs11Key rsaKey = session.GenerateKeyPair(Pkcs11KeyPairSpec.Rsa(2048), "smoke-rsa", [1]);
        var rsa = (IRsaKey)rsaKey;
        foreach (SignatureSpec spec in new[] { SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256), SignatureSpec.RsaPss(HashAlgorithmName.SHA256) })
        {
            if (!spec.Verify(rsa.PublicKey, message, rsa.Sign(message, spec)).IsValid)
            {
                return false;
            }
        }

        byte[] secret = RandomNumberGenerator.GetBytes(32);
        using (RSA pub = rsa.PublicKey.ToRsa())
        {
            if (!rsa.Decrypt(pub.Encrypt(secret, RSAEncryptionPadding.OaepSHA1), DecryptionSpec.RsaOaep(HashAlgorithmName.SHA1)).AsSpan().SequenceEqual(secret))
            {
                return false;
            }
        }

        Pkcs11Key ecKey = session.GenerateKeyPair(Pkcs11KeyPairSpec.P256(), "smoke-ec", [2]);
        var ec = (ISigningKey)ecKey;
        SignatureSpec ecSpec = SignatureSpec.Ecdsa(HashAlgorithmName.SHA256);
        if (!ecSpec.Verify(ec.PublicKey, message, ec.Sign(message, ecSpec)).IsValid)
        {
            return false;
        }

        using var peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var tokenPublic = ECDiffieHellman.Create();
        tokenPublic.ImportSubjectPublicKeyInfo(ec.PublicKey.Encoded.Span, out _);
        if (!((IAgreementKey)ecKey).Agree(PublicKeyInfo.FromAsymmetricAlgorithm(peer)).AsSpan().SequenceEqual(peer.DeriveRawSecretAgreement(tokenPublic.PublicKey)))
        {
            return false;
        }

        try
        {
            _ = session.SignRaw(rsaKey, 0xDEADBEEF, null, message);
            return false;
        }
        catch (Pkcs11MechanismException)
        {
        }

        Console.WriteLine("pkcs11 smoke: ok (" + m.Info.Manufacturer + " " + m.Info.LibraryVersion + ")");
        return true;
    }
}
