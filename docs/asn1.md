# ASN.1 and PEM reading and writing

Normative behaviour of `RecursiveAI.OneCrypto.Asn1` and `RecursiveAI.OneCrypto.Pem`. Clause numbers are ITU-T X.690 (02/2021) unless another document is named.

## Rules

| Rules | Accepts |
|---|---|
| `Ber` | Every valid BER encoding: long-form lengths with leading zeros (8.1.3.5), indefinite lengths for constructed elements (8.1.3.6), constructed BIT STRING, OCTET STRING and character strings (8.6.4, 8.7.3, 8.23.6), any non-zero BOOLEAN as TRUE (8.2.2), UTCTime and GeneralizedTime with an offset, without seconds, or with a fraction. |
| `Cer` | BER restricted by clause 9 and 11: indefinite length on constructed elements and definite on primitives, fewest length octets, primitive strings of at most 1000 octets, the clause 11 value rules. SET OF order is checked; SET order is not. |
| `Der` | BER restricted by clause 10 and 11: definite lengths in the fewest octets, no constructed strings, BOOLEAN TRUE is 0xFF, unused BIT STRING bits are zero (11.2.1), SET OF members ascending (11.6; the shorter encoding is padded with zero octets for the comparison), times end in `Z` with seconds present and no trailing zero in a fraction (11.7, 11.8). |

Under every rule: identifier octets use the single-octet form for tag numbers below 31 and the first subsequent group is not 0x80 (8.1.2.2, 8.1.2.4.2); the length octet 0xFF is refused (8.1.3.5 c); an indefinite length on a primitive is refused; INTEGER and ENUMERATED are minimal (8.3.2); OBJECT IDENTIFIER subidentifiers are minimal (8.19.2); NULL is empty; a BIT STRING has 0 to 7 unused bits and none when empty (8.6.2.2, 8.6.2.3); universal tag 0 is not an element (8.1.5).

A SET (as against SET OF) is not checked for the tag order of 10.3: the order depends on the ASN.1 module, which the reader does not have.

## Reading

`Asn1Reader` is a forward-only `ref struct` over a `ReadOnlySpan<byte>`. Reads of fixed-size and span-returning types allocate nothing. `ReadEncodedValue` returns the element exactly as it appears, header and end-of-contents included: hash that, never a re-encoding. `Asn1Element` holds the same slices as `ReadOnlyMemory<byte>` for the model layers. `Asn1StreamReader` yields tokens from a `Stream` in constant memory (16 KiB buffer) and gives a constructed OCTET STRING of any size as a `Stream`.

Every `TryRead…` leaves the position unchanged on failure and sets `LastFailure` (reason and offset). The throwing twin raises `Asn1ParseException` with the same reason and offset. Reading never throws another exception type on malformed input.

### Limits (`Asn1Limits`, on by default)

| Limit | Default | Applies to |
|---|---|---|
| `MaxDepth` | 64 | nesting of constructed elements, including the scan for the end of an indefinite length, and the stream reader's open elements |
| `MaxScanElements` | 1,048,576 | elements examined to find one indefinite end, and segments of one constructed string |
| `MaxTotalSize` | 64 GiB | a span longer than this is refused; the stream reader stops after this many octets |
| `MaxCopiedLength` | 256 MiB | arrays built by joining constructed strings or by `Asn1StreamReader.ReadContent` |
| `MaxStringNesting` | 4 | nested levels of constructed string segments |

An element length is checked against the data that remains before a slice or array is made, so a hostile length cannot cause an allocation. Finding the end of an indefinite-length element is linear: definite-length children are skipped whole and open indefinite elements are counted, not recursed into.

### Differences from `System.Formats.Asn1.AsnReader`

Found by the differential run (`tests/OneCrypto.Tests/Asn1/DifferentialTests.cs`) and kept on purpose:

1. **Universal tag 0** is rejected as an element (8.1.5 reserves it for the end-of-contents octets). `AsnReader` reads it as an ordinary element. The differential harness makes the oracle refuse it too, so that this one cause does not hide others.
2. **BIT STRING unused bits** are returned as received in BER (8.6.2.4 leaves their value unspecified, and lossless handling keeps them); `AsnReader` clears them. The harness masks them before comparing.
3. **GeneralizedTime fractions** are exact to 100 ns; `AsnReader` computes them in floating point and is occasionally one tick (100 ns) lower. The harness accepts a one-tick difference.
4. **Fractions of a minute or hour** in BER GeneralizedTime (X.680 clause 46) are refused; `AsnReader` reads them. No profile in use writes them.
5. **Object identifier arcs** are decoded up to 128 bits (enough for `2.25.<UUID>`); larger arcs give `ValueOutOfRange`. `AsnReader` has no limit. The lenient `Asn1Values.TryOid` keeps a 64-bit limit.
6. **UniversalString** is decoded (UCS-4, 8.23.7); `AsnReader` does not support it. T61String and GeneralString decode as Latin-1.
7. **Long object identifiers**: this library reads any length (the span form, `ReadObjectIdentifierBytes`, allocates nothing); `AsnReader` refuses a dotted form of more than 127 characters. The harness applies the same cut-off to this library before comparing.
8. A two-digit UTCTime year of 50 to 99 is 19xx and 00 to 49 is 20xx (RFC 5280 clause 4.1.2.5.1), as in `AsnReader`'s default. A second of 60 is refused by both.

## Writing

`Asn1Writer` builds DER (default) or definite-length BER in one buffer: `Push…`/`Pop` write the length in front of the content in its shortest form; a SET OF opened with `PushSetOf` is sorted when it closes (11.6). `BerStreamWriter` writes indefinite-length BER to a `Stream` so a payload of any size goes out in segments. `DerWriter` is the static helper for building small structures bottom-up and for the CMS and time-stamp code.

## PEM (RFC 7468)

`PemEncoding.Parse`/`ParseAll` (throwing, `PemFormatException` with reason and offset) and `TryParse`/`TryParseAll`, on text or UTF-8 bytes.

* **Strict** (RFC 7468 clause 3): `-----BEGIN label-----` at the start of a line, base64 in lines of exactly 64 characters except the last (1 to 64), no whitespace inside a line, LF or CRLF line ends, no encapsulation headers, END label equal to BEGIN label. Explanatory text before, between and after blocks is skipped.
* **Lax** (clause 2): any whitespace and line length in the body, a missing final newline, and the legacy `Name: value` encapsulation headers of RFC 1421 clause 4.4 as OpenSSL writes them (`Proc-Type: 4,ENCRYPTED`, `DEK-Info: cipher,iv`), which are returned as `PemBlock.Headers`; a blank line ends them. The body of an encrypted block is not decrypted here.
* A decoded block is limited to 64 MiB. Base64 padding must be correct in both modes.

`PemEncoding.Write` writes LF line ends, 64-column lines and a trailing newline.
