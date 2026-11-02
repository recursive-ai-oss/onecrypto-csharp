using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Internal;

namespace OneCrypto.Tests.Fallbacks;

/// <summary>
/// How a platform's refusal to import an EC public key is reported. Windows CNG throws PlatformNotSupportedException for a point that is not on a
/// curve it has; OpenSSL throws CryptographicException. Both must reach callers as the same typed result, while a curve the platform lacks stays
/// AlgorithmNotSupported. The Windows exception cannot be provoked on other systems, so the mapping is tested directly.
/// </summary>
public class EcImportFailureTests
{
    private static readonly PlatformNotSupportedException Cng = new("The specified curve 'ECDSA_P256' or its parameters are not valid for this platform.");

    [Fact]
    public void ARefusedKeyOnACurveThePlatformHasIsMalformedInput()
    {
        Exception e = Platform.ImportRefused(ECCurve.NamedCurves.nistP256, "EC key import", Cng);
        Assert.IsType<CryptographicException>(e);
        Assert.Same(Cng, e.InnerException);
    }

    [Fact]
    public void ARefusedKeyOnACurveThePlatformLacksIsAPlatformGap()
    {
        // An unnamed curve stands for one the platform cannot make a key on.
        Exception e = Platform.ImportRefused(default, "EC key import", Cng);
        Assert.IsType<AlgorithmNotSupportedException>(e);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void APointThatIsNotOnTheCurveIsACryptographicException(bool ecdh)
    {
        var p = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = new byte[32], Y = new byte[32] },
        };
        p.Q.X[31] = 1;
        p.Q.Y[31] = 2;
        if (ecdh)
        {
            Assert.ThrowsAny<CryptographicException>(() => Platform.CreateEcdh(p, "test"));
        }
        else
        {
            Assert.ThrowsAny<CryptographicException>(() => Platform.CreateEcdsa(p, "test"));
        }
    }
}
