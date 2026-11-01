using System.Text;
using RecursiveAI.OneCrypto.OpenPgp;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace OneCrypto.Smoke;

/// <summary>Parses a published v6 certificate through armor, packets and the transferable-key model.</summary>
internal static class OpenPgpSmoke
{
    private const string Cert = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
-----END PGP PUBLIC KEY BLOCK-----
""";

    public static bool Run()
    {
        ArmorBlock block = Armor.Decode(Encoding.ASCII.GetBytes(Cert));
        TransferableKey key = TransferableKey.Parse(PacketParser.ParseAll(block.Data));
        return key.Primary.Version == 6
            && key.Primary.FingerprintHex == "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"
            && key.Subkeys.Count == 1;
    }

    // The published v6 sample secret key (an Ed25519 primary and an X25519 subkey, not protected).
    private const string SecretKey = """
-----BEGIN PGP PRIVATE KEY BLOCK-----

xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB
exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ
BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh
RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe
7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/
LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG
GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE
M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr
k0mXubZvyl4GBg==
-----END PGP PRIVATE KEY BLOCK-----
""";

    /// <summary>Signs and encrypts, then decrypts and verifies, with version 6 keys and the AEAD message format; also a detached signature.</summary>
    public static bool RunMessages()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        PgpCertificate secret = PgpCertificate.Parse(Encoding.ASCII.GetBytes(SecretKey));
        PgpCertificate pub = PgpCertificate.Parse(secret.ExportPublic());
        using PgpSecretKey signer = PgpSecretKey.Unlock(secret.Primary);
        byte[] data = Encoding.UTF8.GetBytes("smoke message");
        using var enc = new MemoryStream();
        PgpMessageWriter.Write(new MemoryStream(data), enc, new PgpWriteOptions { Now = now, Recipients = [pub], Signers = [signer] });
        using var dec = new MemoryStream();
        PgpReadResult r = PgpMessageReader.Read(new MemoryStream(enc.ToArray()), dec, new PgpReadOptions { Now = now, SecretKeys = [secret], Certificates = [pub] });
        using var sig = new MemoryStream();
        PgpMessageWriter.SignDetached(new MemoryStream(data), sig, new PgpWriteOptions { Now = now, Signers = [signer] });
        PgpReadResult v = PgpMessageReader.VerifyDetached(new MemoryStream(data), new MemoryStream(sig.ToArray()), new PgpReadOptions { Now = now, Certificates = [pub] });
        return dec.ToArray().AsSpan().SequenceEqual(data) && r.Signatures.Count == 1 && r.Signatures[0].IsValid && v.Signatures.Count == 1 && v.Signatures[0].IsValid;
    }

    /// <summary>
    /// Generates version 6 and version 4 keys, protects one with a password, certifies a User ID, revokes a key and finishes a two-phase signature, then checks
    /// each result by using it.
    /// </summary>
    public static bool RunKeyManagement()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        byte[] password = Encoding.UTF8.GetBytes("smoke");
        PgpCertificate alice = PgpKeyGenerator.Generate(new PgpKeyGenerationOptions { Now = now, UserIds = ["Alice"], Password = password });
        PgpCertificate bob = PgpKeyGenerator.Generate(new PgpKeyGenerationOptions { Now = now, UserIds = ["Bob"], Profile = PgpKeyProfile.Rfc4880Curve25519 });
        PgpCertificate pub = alice.ToPublicCertificate();
        using PgpSecretKey aliceKey = PgpSecretKey.Unlock(alice.Primary, [password]);
        using PgpSecretKey bobKey = PgpSecretKey.Unlock(bob.Primary);
        PgpCertificate certified = PgpKeyEditor.Certify(pub, "Alice", bobKey, now.AddDays(1));
        bool certifiedOk = PgpUserIds.IsCertified(certified, "Alice", [bob.ToPublicCertificate()], now.AddDays(2));
        PgpCertificate revoked = PgpKeyEditor.RevokeKey(pub, aliceKey, PgpRevocationReason.None, "", now.AddDays(3));
        bool revokedOk = !revoked.Primary.StateAt(now.AddDays(4)).IsValid;
        byte[] data = Encoding.UTF8.GetBytes("two phase");
        PgpPreparedSignature prepared = PgpPreparedSignature.Decode(PgpPreparedSignature.PrepareDetached(pub.Primary, new MemoryStream(data), now.AddDays(1)).Encode());
        byte[] signature = prepared.SignWith(aliceKey.SigningKey);
        PgpReadResult v = PgpMessageReader.VerifyDetached(new MemoryStream(data), new MemoryStream(signature), new PgpReadOptions { Now = now.AddDays(1), Certificates = [pub] });
        return certifiedOk && revokedOk && v.Signatures.Count == 1 && v.Signatures[0].IsValid;
    }
}
