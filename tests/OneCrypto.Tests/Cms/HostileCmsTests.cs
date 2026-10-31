using OneCrypto.Fuzz;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Cms;
using static OneCrypto.Tests.Support.CmsFixture;

namespace OneCrypto.Tests.Cms;

/// <summary>Damaged and mutated signatures give reports, not exceptions.</summary>
public class HostileCmsTests
{
    [Fact]
    public void DamagedSignerCertificateIsReportedNotThrown()
    {
        // The signer certificate keeps its issuer and serial (so it is still matched to the signer) but a byte inside it is wrong.
        // Some platforms parse certificates lazily, so the damage only shows when a property is read.
        byte[] cms = KitSign(TestPki.Shared.RsaSigner, new CmsSpec { Cades = true });
        byte[] signerDer = TestPki.Shared.RsaSigner.RawData;
        int certAt = cms.AsSpan().IndexOf(signerDer);
        Assert.True(certAt > 0);

        // The signature algorithm OID (06 09 2A 86 48 86 F7 0D 01 01 0B) inside the certificate: break its tag.
        byte[] oid = Convert.FromHexString("06092A864886F70D01010B");
        int oidAt = certAt + signerDer.AsSpan().IndexOf(oid);
        Assert.InRange(oidAt, certAt, certAt + signerDer.Length);
        byte[] broken = (byte[])cms.Clone();
        broken[oidAt + 1] = 0x37;
        CmsSignerResult v = VerifyOne(broken);
        Assert.False(v.IsValid);
        Assert.NotEqual(CmsCheckStatus.Valid, v.SignatureCheck);

        // Every few bytes of the certificate, damaged one at a time: always a result, never an exception.
        for (int i = 4; i < signerDer.Length; i += 7)
        {
            byte[] copy = (byte[])cms.Clone();
            int p = certAt + i;
            copy[p] = copy[p] == 0xFF ? (byte)0 : (byte)0xFF;
            Assert.NotNull(VerifyOne(copy).Warnings);
        }
    }

    [Fact]
    public void MutatedSignaturesNeverThrow()
    {
        byte[] cms = KitSign(TestPki.Shared.RsaSigner, new CmsSpec { Cades = true, Timestamp = true });
        var rng = new Random(1234);
        for (int i = 0; i < 400; i++)
        {
            byte[] copy = (byte[])cms.Clone();
            int n = 1 + rng.Next(3);
            for (int k = 0; k < n; k++)
            {
                copy[rng.Next(copy.Length)] = (byte)rng.Next(256);
            }

            _ = VerifyOne(copy).IsValid;
        }
    }

    [Fact]
    public void FuzzTargetSurvivesMutatedSeeds()
    {
        var rng = new Random(99);
        foreach (byte[] seed in CmsTarget.Seeds())
        {
            CmsTarget.Run(seed);
            for (int i = 0; i < 60; i++)
            {
                byte[] copy = (byte[])seed.Clone();
                for (int k = 0; k < 1 + rng.Next(4); k++)
                {
                    copy[1 + rng.Next(copy.Length - 1)] = (byte)rng.Next(256);
                }

                CmsTarget.Run(copy);
            }
        }
    }
}
