using System.Text;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Tests.Primitives;

public class Argon2PhcTests
{
    // RFC 9106 §5.3: Argon2id, m=32, t=3, p=4, password 32 x 0x01, salt 16 x 0x02, tag 32 bytes (secret and associated data are not part of a PHC string, so the tag is recomputed here).
    private static readonly byte[] Password = Enumerable.Repeat((byte)1, 32).ToArray();
    private static readonly byte[] Salt = Enumerable.Repeat((byte)2, 16).ToArray();

    [Fact]
    public void FormatsAndParsesAndVerifies()
    {
        foreach (Argon2Type t in new[] { Argon2Type.Argon2d, Argon2Type.Argon2i, Argon2Type.Argon2id })
        {
            byte[] tag = Argon2.DeriveKey(t, Password, Salt, 32, 3, 4, 32);
            string phc = Argon2Phc.Format(new Argon2PhcHash(t, 32, 3, 4, Salt, tag));
            Assert.StartsWith($"${t.ToString().ToLowerInvariant()}$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$", phc, StringComparison.Ordinal);
            Argon2PhcHash back = Argon2Phc.Parse(phc);
            Assert.Equal(t, back.Type);
            Assert.Equal(Salt, back.Salt);
            Assert.Equal(tag, back.Hash);
            Assert.Equal(phc, Argon2Phc.Format(back));
            Assert.True(Argon2Phc.Verify(Password, phc));
            Assert.False(Argon2Phc.Verify(Encoding.UTF8.GetBytes("wrong"), phc));
        }
    }

    [Fact]
    public void Rfc9106TagInPhcForm()
    {
        // The RFC's Argon2id tag needs secret and associated data; check the string form with that known tag (0d640df5…e659).
        byte[] tag = Convert.FromHexString("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
        string phc = Argon2Phc.Format(new Argon2PhcHash(Argon2Type.Argon2id, 32, 3, 4, Salt, tag));
        Assert.Equal("$argon2id$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk", phc);
        Assert.Equal(tag, Argon2Phc.Parse(phc).Hash);
    }

    [Fact]
    public void HashThenVerify()
    {
        string phc = Argon2Phc.Hash(Argon2Type.Argon2id, Password, 64, 2, 1);
        Assert.True(Argon2Phc.Verify(Password, phc));
        Assert.False(Argon2Phc.Verify(Salt, phc));
    }

    [Theory]
    [InlineData("", Argon2PhcError.Malformed)]
    [InlineData("argon2id", Argon2PhcError.Malformed)]
    [InlineData("$argon2id$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg", Argon2PhcError.Malformed)]
    [InlineData("$argon2x$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk", Argon2PhcError.UnknownAlgorithm)]
    [InlineData("$argon2id$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk", Argon2PhcError.UnsupportedVersion)]
    [InlineData("$argon2id$v=16$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk", Argon2PhcError.UnsupportedVersion)]
    [InlineData("$argon2id$v=19$t=3,m=32,p=4$AgICAgICAgICAgICAgICAg$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk", Argon2PhcError.BadParameter)]
    [InlineData("$argon2id$v=19$m=32,t=3$AgICAgICAgICAgICAgICAg$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk", Argon2PhcError.BadParameter)]
    [InlineData("$argon2id$v=19$m=032,t=3,p=4$AgICAgICAgICAgICAgICAg$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk", Argon2PhcError.BadParameter)]
    [InlineData("$argon2id$v=19$m=+32,t=3,p=4$AgICAgICAgICAgICAgICAg$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk", Argon2PhcError.BadParameter)]
    [InlineData("$argon2id$v=19$m=99999999999,t=3,p=4$AgICAgICAgICAgICAgICAg$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk", Argon2PhcError.BadParameter)]
    [InlineData("$argon2id$v=19$m=31,t=3,p=4$AgICAgICAgICAgICAgICAg$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk", Argon2PhcError.BadParameter)]
    [InlineData("$argon2id$v=19$m=32,t=0,p=4$AgICAgICAgICAgICAgICAg$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk", Argon2PhcError.BadParameter)]
    [InlineData("$argon2id$v=19$m=32,t=3,p=4,keyid=AA$AgICAgICAgICAgICAgICAg$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk", Argon2PhcError.Unsupported)]
    [InlineData("$argon2id$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg==$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk", Argon2PhcError.BadEncoding)]
    [InlineData("$argon2id$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAh$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk", Argon2PhcError.BadEncoding)]
    [InlineData("$argon2id$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5ll", Argon2PhcError.BadEncoding)]
    [InlineData("$argon2id$v=19$m=32,t=3,p=4$AgICAgI$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk", Argon2PhcError.BadEncoding)]
    [InlineData("$argon2id$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk$x", Argon2PhcError.Malformed)]
    [InlineData("$argon2id$v=19$m=32,t=3,p=4$Ag-CAgICAgICAgICAgICAg$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk", Argon2PhcError.BadEncoding)]
    public void MalformedStringsRaiseTypedErrors(string phc, Argon2PhcError expected)
    {
        Argon2PhcFormatException e = Assert.Throws<Argon2PhcFormatException>(() => Argon2Phc.Parse(phc));
        Assert.Equal(expected, e.Error);
        Assert.False(Argon2Phc.TryParse(phc, out Argon2PhcHash? v));
        Assert.Null(v);
    }

    [Fact]
    public void CostAboveLimitsIsRefusedBeforeAllocation()
    {
        string phc = "$argon2id$v=19$m=999999999,t=3,p=4$AgICAgICAgICAgICAgICAg$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk";
        Assert.Throws<KdfLimitExceededException>(() => Argon2Phc.Verify(Password, phc));
    }

    [Fact]
    public void OverlongStringIsRefused()
        => Assert.Equal(Argon2PhcError.Malformed, Assert.Throws<Argon2PhcFormatException>(() => Argon2Phc.Parse("$" + new string('a', 2000))).Error);
}
