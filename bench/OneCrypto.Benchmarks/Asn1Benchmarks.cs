using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using RecursiveAI.OneCrypto.Asn1;
using OurTag = RecursiveAI.OneCrypto.Asn1.Asn1Tag;
using TheirTag = System.Formats.Asn1.Asn1Tag;

namespace OneCrypto.Benchmarks;

/// <summary>
/// ASN.1 parse against System.Formats.Asn1's AsnReader on the same bytes and the same work: both sides walk the whole structure,
/// enter every constructed element and decode every primitive with the typed read for its universal type (strings and
/// object identifiers become .NET strings on both sides).
/// </summary>
[MemoryDiagnoser]
public class Asn1Benchmarks
{
    private byte[] _cert = [];
    private byte[] _large = [];

    [GlobalSetup]
    public void Setup()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Bench Test, O=Example, C=US", ec, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("example.test");
        san.AddDnsName("www.example.test");
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        using X509Certificate2 cert = req.CreateSelfSigned(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero));
        _cert = cert.RawData;

        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            for (int i = 0; i < 50_000; i++)
            {
                using (w.PushSequence())
                {
                    w.WriteInteger(i * 7919L);
                    w.WriteOctetString(new byte[20 + (i % 13)]);
                    w.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                }
            }
        }

        _large = w.Encode();
    }

    [Benchmark(Baseline = true)]
    public int CertificateAsnReader() => TheirWalk(new AsnReader(_cert, AsnEncodingRules.DER));

    [Benchmark]
    public int CertificateOurs() => OurWalk(new Asn1Reader(_cert, Asn1Rules.Der));

    [Benchmark]
    public int LargeSequenceAsnReader() => TheirWalk(new AsnReader(_large, AsnEncodingRules.DER));

    [Benchmark]
    public int LargeSequenceOurs() => OurWalk(new Asn1Reader(_large, Asn1Rules.Der));

    private static int TheirWalk(AsnReader r)
    {
        int n = 0;
        while (r.HasData)
        {
            TheirTag tag = r.PeekTag();
            n++;
            if (tag.TagClass == TagClass.Universal)
            {
                switch ((UniversalTagNumber)tag.TagValue)
                {
                    case UniversalTagNumber.Boolean: n += r.ReadBoolean() ? 1 : 0; continue;
                    case UniversalTagNumber.Integer: n += r.ReadIntegerBytes().Length; continue;
                    case UniversalTagNumber.BitString: r.TryReadPrimitiveBitString(out _, out ReadOnlyMemory<byte> bits); n += bits.Length; continue;
                    case UniversalTagNumber.OctetString: r.TryReadPrimitiveOctetString(out ReadOnlyMemory<byte> oct); n += oct.Length; continue;
                    case UniversalTagNumber.Null: r.ReadNull(); continue;
                    case UniversalTagNumber.ObjectIdentifier: n += r.ReadObjectIdentifier().Length; continue;
                    case UniversalTagNumber.UtcTime: n += (int)(r.ReadUtcTime().Ticks & 1); continue;
                    case UniversalTagNumber.GeneralizedTime: n += (int)(r.ReadGeneralizedTime().Ticks & 1); continue;
                    case UniversalTagNumber.Sequence: n += TheirWalk(r.ReadSequence()); continue;
                    case UniversalTagNumber.Set: n += TheirWalk(r.ReadSetOf()); continue;
                    case UniversalTagNumber.UTF8String or UniversalTagNumber.PrintableString or UniversalTagNumber.IA5String:
                        n += r.ReadCharacterString((UniversalTagNumber)tag.TagValue).Length;
                        continue;
                }
            }

            if (tag.IsConstructed)
            {
                n += TheirWalk(r.ReadSequence(tag));
            }
            else
            {
                n += r.ReadEncodedValue().Length;
            }
        }

        return n;
    }

    private static int OurWalk(Asn1Reader r)
    {
        int n = 0;
        while (r.HasData)
        {
            OurTag tag = r.PeekTag();
            n++;
            if (tag.TagClass == Asn1TagClass.Universal)
            {
                switch (tag.TagNumber)
                {
                    case Asn1Tags.Boolean: n += r.ReadBoolean() ? 1 : 0; continue;
                    case Asn1Tags.IntegerType: n += r.ReadIntegerBytes().Length; continue;
                    case Asn1Tags.BitString: n += r.ReadBitString(out _).Length; continue;
                    case Asn1Tags.OctetString: n += r.ReadOctetString().Length; continue;
                    case Asn1Tags.Null: r.ReadNull(); continue;
                    case Asn1Tags.ObjectIdentifier: n += r.ReadObjectIdentifier().Length; continue;
                    case Asn1Tags.UtcTime: n += (int)(r.ReadUtcTime().Ticks & 1); continue;
                    case Asn1Tags.GeneralizedTime: n += (int)(r.ReadGeneralizedTime().Ticks & 1); continue;
                    case Asn1Tags.Sequence: { Asn1Reader c = r.ReadSequence(); n += OurWalk(c); continue; }
                    case Asn1Tags.Set: { Asn1Reader c = r.ReadSetOf(); n += OurWalk(c); continue; }
                    case Asn1Tags.Utf8String or Asn1Tags.PrintableString or Asn1Tags.Ia5String:
                        n += r.ReadCharacterString(tag.TagNumber).Length;
                        continue;
                }
            }

            if (tag.IsConstructed)
            {
                Asn1Reader c = r.ReadSequence(tag);
                n += OurWalk(c);
            }
            else
            {
                n += r.ReadEncodedValue().Length;
            }
        }

        return n;
    }
}
