using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Tests.Keys;

/// <summary>Damage to a serialised two-phase state: truncations and single-octet changes end in a typed refusal or in a state that still cannot accept a signature meant for another one.</summary>
public class PreparedSignatureTamperTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);

    private static (PreparedSignature State, ISigningKey Key) Make(bool ecdsa)
    {
        ISigningKey key = ecdsa
            ? PrivateKey.FromECDsa(ECDsa.Create(ECCurve.NamedCurves.nistP256), ownsKey: true)
            : PrivateKey.FromEd25519(Ed25519PrivateKey.FromSeed(RandomNumberGenerator.GetBytes(32)), ownsKey: true);
        PreparedSignature state = PreparedSignature.Prepare(key.PublicKey, key.DefaultSpec, "the document"u8, CryptoPolicy.Standard, Now, "test-purpose");
        return (state, key);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EveryTruncationAndOctetChangeIsATypedResult(bool ecdsa)
    {
        (PreparedSignature state, ISigningKey key) = Make(ecdsa);
        using (key)
        {
            byte[] encoded = state.Encode();
            byte[] signature = state.SignWith(key);

            for (int n = 0; n < encoded.Length; n++)
            {
                Assert.False(PreparedSignature.TryDecode(encoded.AsSpan(0, n), out _, out string? why), $"truncation to {n}");
                Assert.NotEmpty(why!);
                Assert.Throws<FormatException>(() => PreparedSignature.Decode(encoded.AsSpan(0, n)));
            }

            // Appended octets are refused too (a state is one DER value).
            Assert.False(PreparedSignature.TryDecode([.. encoded, 0], out _, out _));

            for (int i = 0; i < encoded.Length; i++)
            {
                foreach (byte mask in new byte[] { 0x01, 0x80, 0xFF })
                {
                    byte[] m = (byte[])encoded.Clone();
                    m[i] ^= mask;
                    if (!PreparedSignature.TryDecode(m, out PreparedSignature? damaged, out _))
                    {
                        continue;
                    }

                    // A damaged state that still reads must not take over a signature made for the original: only a change of the label may leave it valid.
                    if (damaged!.TryComplete(signature, out _, out _))
                    {
                        Assert.True(state.Purpose != damaged.Purpose || damaged.Encode().AsSpan().SequenceEqual(encoded), $"octet {i} ^ {mask:X2}: {Convert.ToHexString(damaged.Encode())} vs {Convert.ToHexString(encoded)}");
                        Assert.Equal(state.PublicKey, damaged.PublicKey);
                        Assert.Equal(state.Spec, damaged.Spec);
                    }
                }
            }
        }
    }

    [Fact]
    public void AStateHoldsNoSecret()
    {
        (PreparedSignature state, ISigningKey key) = Make(false);
        using (key)
        {
            byte[] seed = RandomNumberGenerator.GetBytes(32);
            using ISigningKey known = PrivateKey.FromEd25519(Ed25519PrivateKey.FromSeed(seed), ownsKey: true);
            PreparedSignature s = PreparedSignature.Prepare(known.PublicKey, known.DefaultSpec, "x"u8, CryptoPolicy.Standard, Now);
            Assert.True(s.Encode().AsSpan().IndexOf(seed) < 0);
        }
    }

    [Fact]
    public void ADigestStateCannotBeMadeToSignOtherDataByEditingItsDataField()
    {
        using ISigningKey key = PrivateKey.FromECDsa(ECDsa.Create(ECCurve.NamedCurves.nistP256), ownsKey: true);
        PreparedSignature state = PreparedSignature.Prepare(key.PublicKey, key.DefaultSpec, "original"u8, CryptoPolicy.Standard, Now);
        PreparedSignature other = PreparedSignature.Prepare(key.PublicKey, key.DefaultSpec, "another"u8, CryptoPolicy.Standard, Now);
        byte[] forOther = other.SignWith(key);
        Assert.Throws<InvalidSignatureException>(() => state.Complete(forOther));
    }
}
