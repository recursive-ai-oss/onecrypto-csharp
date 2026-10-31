using System.Numerics;
using RecursiveAI.OneCrypto.Asn1;

namespace OneCrypto.Tests.Asn1;

public class Asn1ReaderTests
{
    private static byte[] H(string hex) => Convert.FromHexString(hex.Replace(" ", string.Empty));

    [Fact]
    public void ReadsTheCommonTypes()
    {
        // SEQUENCE { INTEGER 5, BOOLEAN TRUE, NULL, OID 1.2.840.113549, BIT STRING 0b101 (5 unused bits), OCTET STRING, UTF8String, [0] EXPLICIT INTEGER 7 }
        byte[] data = H("3030 020105 0101FF 0500 06062A864886F70D 03020560 0402AABB 0C026869 A003020107 170D3236303130323033303430355A");
        var r = new Asn1Reader(data, Asn1Rules.Der);
        Asn1Reader s = r.ReadSequence();
        Assert.False(r.HasData);
        Assert.Equal(new BigInteger(5), s.ReadInteger());
        Assert.True(s.ReadBoolean());
        s.ReadNull();
        Assert.Equal("1.2.840.113549", s.ReadObjectIdentifier());
        Assert.Equal(new byte[] { 0x60 }, s.ReadBitString(out int unused).ToArray());
        Assert.Equal(5, unused);
        Assert.Equal(new byte[] { 0xAA, 0xBB }, s.ReadOctetString().ToArray());
        Assert.Equal("hi", s.ReadCharacterString(Asn1Tags.Utf8String));
        Asn1Reader ex = s.ReadSequence(Asn1Tag.Context(0, true));
        Assert.Equal(7, ex.ReadInt32());
        Assert.Equal(new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero), s.ReadUtcTime());
        s.ThrowIfNotEmpty();
    }

    [Fact]
    public void RawElementAccessReturnsTheOriginalBytesEvenForNonCanonicalBer()
    {
        // A SEQUENCE with a long-form length for a short body, and an indefinite-length child.
        byte[] data = H("30 81 0A 30 80 04 01 41 00 00 02 01 09");
        var r = new Asn1Reader(data);
        Assert.Equal(data, r.ReadEncodedValue().ToArray());
        var r2 = new Asn1Reader(data);
        Asn1Reader s = r2.ReadSequence();
        Assert.Equal(H("30 80 04 01 41 00 00"), s.ReadEncodedValue().ToArray());
        Assert.Equal(H("02 01 09"), s.ReadEncodedValue().ToArray());
    }

    [Fact]
    public void UnknownElementsAreSkippedAndKept()
    {
        byte[] data = H("30 0C A1 03 02 01 05 DF 81 00 01 AA 05 00");
        Asn1Reader s = new Asn1Reader(data, Asn1Rules.Der).ReadSequence();
        Assert.Equal(H("A1 03 02 01 05"), s.ReadEncodedValue().ToArray());
        Assert.Equal(new Asn1Tag(Asn1TagClass.Private, 128), s.PeekTag());
        s.SkipValue();
        s.ReadNull();
        Assert.False(s.HasData);
    }

    [Theory]
    [InlineData("30", Asn1Error.Truncated)]
    [InlineData("", Asn1Error.Truncated)]
    [InlineData("3084FFFFFFFF", Asn1Error.LengthExceedsData)]
    [InlineData("3085010000000 0", Asn1Error.LengthExceedsData)]
    [InlineData("0482 7FFF 01", Asn1Error.LengthExceedsData)]
    [InlineData("3088 FFFFFFFFFFFFFFFF", Asn1Error.LengthExceedsData)]
    [InlineData("30FF", Asn1Error.InvalidLength)]
    [InlineData("0480 0000", Asn1Error.InvalidLength)]
    [InlineData("1F80 01 00", Asn1Error.NonMinimalTag)]
    [InlineData("1F1E 00", Asn1Error.NonMinimalTag)]
    [InlineData("1FFFFFFFFFFF7F 00", Asn1Error.InvalidTag)]
    [InlineData("0000", Asn1Error.InvalidTag)]
    public void MalformedHeadersAreTypedErrors(string hex, Asn1Error expected)
    {
        byte[] data = H(hex);
        var r = new Asn1Reader(data);
        Assert.False(r.TryReadEncodedValue(out _));
        Assert.Equal(expected, r.LastFailure.Error);
        Assert.Equal(0, r.Offset);
        var r2 = new Asn1Reader(data);
        Asn1ParseException ex = Assert.Throws<Asn1ParseException>(() => new Asn1Reader(data).ReadEncodedValue());
        Assert.Equal(expected, ex.Error);
        _ = r2;
    }

    [Fact]
    public void DerRejectsNonMinimalLengthsAndIndefiniteForms()
    {
        Assert.Equal(Asn1Error.NonMinimalLength, Fail("04 81 01 AA", Asn1Rules.Der));
        Assert.Equal(Asn1Error.NonMinimalLength, Fail("04 82 00 01 AA", Asn1Rules.Der));
        Assert.Equal(Asn1Error.NonMinimalLength, Fail("04 81 05 AA", Asn1Rules.Der));
        Assert.Equal(Asn1Error.LengthFormNotAllowed, Fail("30 80 00 00", Asn1Rules.Der));
        Assert.Equal(Asn1Error.None, Fail("04 81 01 AA", Asn1Rules.Ber));
        Assert.Equal(Asn1Error.None, Fail("30 80 00 00", Asn1Rules.Ber));
    }

    private static Asn1Error Fail(string hex, Asn1Rules rules)
    {
        var r = new Asn1Reader(H(hex), rules);
        return r.TryReadEncodedValue(out _) ? Asn1Error.None : r.LastFailure.Error;
    }

    [Fact]
    public void NestingBeyondTheLimitIsRefusedWhetherDefiniteOrIndefinite()
    {
        // 100 nested definite SEQUENCEs.
        var d = new List<byte>();
        for (int i = 0; i < 100; i++)
        {
            d.AddRange(new byte[] { 0x30, 0x80 });
        }

        for (int i = 0; i < 100; i++)
        {
            d.AddRange(new byte[] { 0, 0 });
        }

        var r = new Asn1Reader(d.ToArray(), Asn1Rules.Ber, new Asn1Limits { MaxDepth = 16 });
        Assert.False(r.TryReadEncodedValue(out _));
        Assert.Equal(Asn1Error.DepthExceeded, r.LastFailure.Error);

        // Definite nesting: each level wraps the previous.
        byte[] inner = [0x05, 0x00];
        for (int i = 0; i < 40; i++)
        {
            inner = DerWriter.Sequence(inner);
        }

        var walk = new Asn1Reader(inner, Asn1Rules.Der, new Asn1Limits { MaxDepth = 16 });
        int levels = 0;
        while (walk.TryReadSequence(out Asn1Reader child))
        {
            walk = child;
            levels++;
        }

        Assert.Equal(16, levels);
        Assert.Equal(Asn1Error.DepthExceeded, walk.LastFailure.Error);
    }

    [Fact]
    public void LimitsOnTotalSizeAndScanWork()
    {
        var r = new Asn1Reader(new byte[100], Asn1Rules.Ber, new Asn1Limits { MaxTotalSize = 50 });
        Assert.False(r.TryReadEncodedValue(out _));
        Assert.Equal(Asn1Error.TotalSizeExceeded, r.LastFailure.Error);

        var data = new List<byte> { 0x30, 0x80 };
        for (int i = 0; i < 1000; i++)
        {
            data.AddRange(new byte[] { 5, 0 });
        }

        data.AddRange(new byte[] { 0, 0 });
        var r2 = new Asn1Reader(data.ToArray(), Asn1Rules.Ber, new Asn1Limits { MaxScanElements = 100 });
        Assert.False(r2.TryReadEncodedValue(out _));
        Assert.Equal(Asn1Error.TooManyElements, r2.LastFailure.Error);
    }

    [Fact]
    public void DerRejectsNonCanonicalValues()
    {
        Assert.Equal(Asn1Error.NotCanonical, ReadFail("01 01 01", (ref Asn1Reader r) => r.TryReadBoolean(out _)));
        Assert.Equal(Asn1Error.InvalidContent, ReadFail("02 02 00 01", (ref Asn1Reader r) => r.TryReadInteger(out _)));
        Assert.Equal(Asn1Error.InvalidContent, ReadFail("02 02 FF 80", (ref Asn1Reader r) => r.TryReadInteger(out _)));
        Assert.Equal(Asn1Error.InvalidContent, ReadFail("02 00", (ref Asn1Reader r) => r.TryReadInteger(out _)));
        Assert.Equal(Asn1Error.NotCanonical, ReadFail("03 02 04 01", (ref Asn1Reader r) => r.TryReadBitString(out _, out _)));
        Assert.Equal(Asn1Error.InvalidContent, ReadFail("03 02 08 00", (ref Asn1Reader r) => r.TryReadBitString(out _, out _)));
        Assert.Equal(Asn1Error.InvalidContent, ReadFail("03 00", (ref Asn1Reader r) => r.TryReadBitString(out _, out _)));
        Assert.Equal(Asn1Error.ConstructedNotAllowed, ReadFail("24 03 04 01 41", (ref Asn1Reader r) => r.TryReadOctetStringBytes(out _)));
        Assert.Equal(Asn1Error.NotCanonical, ReadFail("17 0B 32363031303230333034 5A", (ref Asn1Reader r) => r.TryReadUtcTime(out _)));
        Assert.Equal(Asn1Error.NotCanonical, ReadFail("18 11 32303236303130323033303430352E30 5A".Replace(" ", string.Empty), (ref Asn1Reader r) => r.TryReadGeneralizedTime(out _)));
        Assert.Equal(Asn1Error.InvalidContent, ReadFail("06 02 2A 80", (ref Asn1Reader r) => r.TryReadObjectIdentifier(out _)));
        Assert.Equal(Asn1Error.InvalidContent, ReadFail("06 03 2A 80 03", (ref Asn1Reader r) => r.TryReadObjectIdentifier(out _)));
        Assert.Equal(Asn1Error.InvalidContent, ReadFail("05 01 00", (ref Asn1Reader r) => r.TryReadNull()));
        Assert.Equal(Asn1Error.NotCanonical, ReadFail("31 06 04 01 02 04 01 01", (ref Asn1Reader r) => r.TryReadSetOf(out _)));

        // Same value accepted in BER.
        var ber = new Asn1Reader(H("01 01 01"), Asn1Rules.Ber);
        Assert.True(ber.ReadBoolean());
    }

    private delegate bool Try(ref Asn1Reader r);

    private static Asn1Error ReadFail(string hex, Try f)
    {
        var r = new Asn1Reader(H(hex), Asn1Rules.Der);
        return f(ref r) ? Asn1Error.None : r.LastFailure.Error;
    }

    [Fact]
    public void ConstructedStringsAreJoinedInBer()
    {
        // Constructed OCTET STRING, indefinite, with a nested constructed segment.
        byte[] data = H("24 80 04 02 AA BB 24 06 04 01 CC 04 01 DD 04 00 00 00");
        var r = new Asn1Reader(data);
        Assert.Equal(H("AA BB CC DD"), r.ReadOctetStringBytes());
        Assert.False(r.HasData);
        var primitiveOnly = new Asn1Reader(data);
        Assert.False(primitiveOnly.TryReadOctetString(out _));
        Assert.Equal(Asn1Error.ConstructedNotAllowed, primitiveOnly.LastFailure.Error);

        // Constructed BIT STRING: only the last segment may have unused bits.
        var bits = new Asn1Reader(H("23 08 03 02 00 FF 03 02 04 F0"));
        Assert.Equal(H("FF F0"), bits.ReadBitStringBytes(out int unused));
        Assert.Equal(4, unused);
        Assert.Equal(Asn1Error.InvalidContent, ReadBer("23 08 03 02 04 F0 03 02 00 FF", (ref Asn1Reader r) => r.TryReadBitStringBytes(out _, out _)));

        // Segment of the wrong type.
        Assert.Equal(Asn1Error.UnexpectedTag, ReadBer("24 03 0C 01 41", (ref Asn1Reader r) => r.TryReadOctetStringBytes(out _)));
    }

    private static Asn1Error ReadBer(string hex, Try f)
    {
        var r = new Asn1Reader(H(hex), Asn1Rules.Ber);
        return f(ref r) ? Asn1Error.None : r.LastFailure.Error;
    }

    [Fact]
    public void IntegersConvertAndStayInRange()
    {
        Assert.Equal(-129, new Asn1Reader(H("02 02 FF 7F")).ReadInt32());
        Assert.Equal(long.MinValue, new Asn1Reader(H("02 08 80 00 00 00 00 00 00 00")).ReadInt64());
        Assert.Equal(ulong.MaxValue, new Asn1Reader(H("02 09 00 FF FF FF FF FF FF FF FF")).ReadUInt64());
        var r = new Asn1Reader(H("02 05 01 00 00 00 00"));
        Assert.False(r.TryReadInt32(out _));
        Assert.Equal(Asn1Error.ValueOutOfRange, r.LastFailure.Error);
        Assert.Equal(new BigInteger(1) << 32, r.ReadInteger());
        Assert.Equal(H("80 00"), new Asn1Reader(H("02 03 00 80 00")).ReadUnsignedIntegerBytes().ToArray());
        Assert.False(new Asn1Reader(H("02 01 80")).TryReadUnsignedIntegerBytes(out _));
    }

    [Fact]
    public void HighTagNumbersRoundTrip()
    {
        foreach (int n in new[] { 0, 30, 31, 127, 128, 16383, 16384, int.MaxValue })
        {
            var tag = new Asn1Tag(Asn1TagClass.Application, n);
            var w = new Asn1Writer();
            w.WriteContent(tag, [1, 2]);
            byte[] enc = w.Encode();
            Assert.Equal(tag.EncodedLength + 3, enc.Length);
            var r = new Asn1Reader(enc, Asn1Rules.Der);
            if (n == 0)
            {
                Assert.Equal(tag, r.PeekTag());
            }

            Assert.Equal(tag, r.PeekTag());
            Assert.Equal(new byte[] { 1, 2 }, r.ReadOctetString(tag).ToArray());
        }
    }

    [Fact]
    public void TimesFollowTheDerAndBerRules()
    {
        DateTimeOffset t(string s, Asn1Rules rules, bool utc)
        {
            byte[] b = System.Text.Encoding.ASCII.GetBytes(s);
            var r = new Asn1Reader([(byte)(utc ? 0x17 : 0x18), (byte)b.Length, .. b], rules);
            return utc ? r.ReadUtcTime() : r.ReadGeneralizedTime();
        }

        Assert.Equal(new DateTimeOffset(1950, 1, 1, 0, 0, 0, TimeSpan.Zero), t("500101000000Z", Asn1Rules.Der, true));
        Assert.Equal(new DateTimeOffset(2049, 12, 31, 23, 59, 59, TimeSpan.Zero), t("491231235959Z", Asn1Rules.Der, true));
        Assert.Equal(new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero).AddTicks(5_000_000), t("20260102030405.5Z", Asn1Rules.Der, false));
        Assert.Equal(new DateTimeOffset(2026, 1, 2, 2, 4, 5, TimeSpan.Zero), t("260102030405+0100", Asn1Rules.Ber, true));
        Assert.Throws<Asn1ParseException>(() => t("260102030405+0100", Asn1Rules.Der, true));
        Assert.Throws<Asn1ParseException>(() => t("20260230000000Z", Asn1Rules.Ber, false));
        Assert.Throws<Asn1ParseException>(() => t("20260102240000Z", Asn1Rules.Ber, false));
        Assert.Throws<Asn1ParseException>(() => t("20260102030460Z", Asn1Rules.Ber, false));
    }

    [Fact]
    public void ReadersNeverThrowOtherExceptionsOnRandomInput()
    {
        var rng = new Random(42);
        for (int i = 0; i < 20000; i++)
        {
            byte[] data = new byte[rng.Next(0, 40)];
            rng.NextBytes(data);
            if (data.Length > 1 && rng.Next(2) == 0)
            {
                data[0] = 0x30;
            }

            foreach (Asn1Rules rules in new[] { Asn1Rules.Ber, Asn1Rules.Cer, Asn1Rules.Der })
            {
                try
                {
                    _ = Differential.Ours(data, rules);
                }
                catch (Exception e) when (e is not Xunit.Sdk.XunitException)
                {
                    Assert.Fail($"{rules} on {Convert.ToHexString(data)}: {e}");
                }
            }
        }
    }
}

public class Asn1WriterTests
{
    [Fact]
    public void NestedElementsGetMinimalLengthsAndSetOfIsSorted()
    {
        var w = new Asn1Writer();
        w.PushSequence();
        w.WriteInteger(300);
        w.PushSetOf();
        w.WriteOctetString([2]);
        w.WriteOctetString([1, 5]);
        w.WriteOctetString([1]);
        w.Pop();
        w.WriteOctetString(new byte[200]);
        w.Pop();
        byte[] der = w.Encode();
        Assert.Equal(0x30, der[0]);
        Assert.Equal(0x81, der[1]);
        var r = new Asn1Reader(der, Asn1Rules.Der);
        Asn1Reader s = r.ReadSequence();
        Assert.Equal(300, s.ReadInt32());
        Asn1Reader set = s.ReadSetOf();
        Assert.Equal(new byte[] { 1 }, set.ReadOctetString().ToArray());
        Assert.Equal(new byte[] { 2 }, set.ReadOctetString().ToArray());
        Assert.Equal(new byte[] { 1, 5 }, set.ReadOctetString().ToArray());
        Assert.Equal(200, s.ReadOctetString().Length);
    }

    [Fact]
    public void OidsTimesAndStringsRead()
    {
        var w = new Asn1Writer();
        w.PushSequence();
        w.WriteObjectIdentifier("2.25.329800735698586629295641978511506172918");
        w.WriteUtcTime(new DateTimeOffset(2030, 5, 6, 7, 8, 9, TimeSpan.Zero));
        w.WriteGeneralizedTime(new DateTimeOffset(2030, 5, 6, 7, 8, 9, TimeSpan.Zero).AddTicks(1_230_000));
        w.WriteCharacterString(Asn1Tags.PrintableString, "Test CA");
        w.WriteBitString([0xA0], 5);
        w.WriteBoolean(true);
        w.WriteUnsignedInteger([0x00, 0x00, 0x80, 0x01]);
        w.Pop();
        var r = new Asn1Reader(w.Encode(), Asn1Rules.Der).ReadSequence();
        Assert.Equal("2.25.329800735698586629295641978511506172918", r.ReadObjectIdentifier());
        Assert.Equal(new DateTimeOffset(2030, 5, 6, 7, 8, 9, TimeSpan.Zero), r.ReadUtcTime());
        Assert.Equal(new DateTimeOffset(2030, 5, 6, 7, 8, 9, TimeSpan.Zero).AddTicks(1_230_000), r.ReadGeneralizedTime());
        Assert.Equal("Test CA", r.ReadCharacterString(Asn1Tags.PrintableString));
        r.ReadBitString(out int unused);
        Assert.Equal(5, unused);
        Assert.True(r.ReadBoolean());
        Assert.Equal(new byte[] { 0x80, 0x01 }, r.ReadUnsignedIntegerBytes().ToArray());
    }

    [Fact]
    public void BerStreamWriterProducesIndefiniteLengthOutputTheReaderTakes()
    {
        var ms = new MemoryStream();
        var w = new BerStreamWriter(ms);
        w.BeginIndefinite(Asn1Tag.Sequence);
        w.WriteDefinite(new Asn1Tag(Asn1Tags.IntegerType), [1]);
        w.WriteOctetStringFrom(new MemoryStream(Enumerable.Range(0, 1000).Select(i => (byte)i).ToArray()), 300);
        w.End();
        Assert.Equal(0, w.OpenCount);
        byte[] enc = ms.ToArray();
        Asn1Reader s = new Asn1Reader(enc).ReadSequence();
        Assert.Equal(1, s.ReadInt32());
        Assert.Equal(Enumerable.Range(0, 1000).Select(i => (byte)i).ToArray(), s.ReadOctetStringBytes());
    }

    [Fact]
    public void PopWithNothingOpenIsAMisuseError()
    {
        Assert.Throws<InvalidOperationException>(() => new Asn1Writer().Pop());
        var w = new Asn1Writer();
        w.PushSequence();
        Assert.Throws<InvalidOperationException>(() => w.Encode());
    }
}
