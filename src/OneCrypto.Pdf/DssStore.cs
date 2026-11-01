using OnePdf;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Pdf;

/// <summary>An object read from the document security store, with the position and reference of its stream in the file.</summary>
/// <typeparam name="T">The model type.</typeparam>
internal readonly record struct StoredItem<T>(T Value, long Offset, PdfReference? Reference);

/// <summary>The /DSS dictionary of a document (EN 319 142-1 §5.4.2.2) and its /VRI entries, read into models.</summary>
internal sealed class DssStore
{
    /// <summary>Most items read from one array, and the most octets of one item.</summary>
    internal const int MaxItems = 2048;

    internal const int MaxItemBytes = 8 << 20;

    private readonly List<string> _warnings = [];

    public List<StoredItem<Certificate>> Certificates { get; } = [];

    public List<StoredItem<CertificateRevocationList>> Crls { get; } = [];

    public List<StoredItem<OcspBasicResponse>> Ocsp { get; } = [];

    /// <summary>The /VRI entries by upper-case hex key.</summary>
    public Dictionary<string, DssStore> Vri { get; } = new(StringComparer.Ordinal);

    /// <summary>True when the document has a /DSS dictionary.</summary>
    public bool Present { get; private set; }

    public IReadOnlyList<string> Warnings => _warnings;

    /// <summary>Reads the store. A malformed item is skipped with a warning; a hostile file cannot make this throw.</summary>
    public static DssStore Read(PdfDocument document)
    {
        var store = new DssStore();
        PdfDictionary? dss;
        try
        {
            dss = document.Catalog.GetDictionary("DSS");
        }
        catch (PdfException e)
        {
            store._warnings.Add("The /DSS entry cannot be read: " + e.Message);
            return store;
        }

        if (dss is null)
        {
            return store;
        }

        store.Present = true;
        store.ReadArrays(dss);
        try
        {
            if (dss.GetDictionary("VRI") is { } vri)
            {
                int count = 0;
                foreach (string key in vri.Keys)
                {
                    if (++count > MaxItems)
                    {
                        store._warnings.Add("The /VRI dictionary has more than " + MaxItems + " entries; the rest are ignored.");
                        break;
                    }

                    if (vri.GetDictionary(key) is { } entry)
                    {
                        var one = new DssStore { Present = true };
                        one.ReadArrays(entry);
                        store.Vri[key.ToUpperInvariant()] = one;
                        store._warnings.AddRange(one._warnings);
                    }
                }
            }
        }
        catch (PdfException e)
        {
            store._warnings.Add("The /VRI dictionary cannot be read: " + e.Message);
        }

        return store;
    }

    private void ReadArrays(PdfDictionary dict)
    {
        // The store names its arrays Certs, CRLs and OCSPs; a VRI entry names them Cert, CRL and OCSP (EN 319 142-1 §5.4.2).
        foreach ((string key, int kind) in new[] { ("Cert", 0), ("CRL", 1), ("OCSP", 2), ("Certs", 0), ("CRLs", 1), ("OCSPs", 2) })
        {
            PdfArray? array;
            try
            {
                array = dict.GetArray(key);
            }
            catch (PdfException)
            {
                continue;
            }

            if (array is null)
            {
                continue;
            }

            for (int i = 0; i < array.Count; i++)
            {
                if (i >= MaxItems)
                {
                    _warnings.Add("/" + key + " has more than " + MaxItems + " items; the rest are ignored.");
                    break;
                }

                try
                {
                    if (array[i] is not PdfStream stream || stream.GetRawBytes().Length > MaxItemBytes)
                    {
                        _warnings.Add("/" + key + " item " + i + " is not a stream of a size the bridge reads.");
                        continue;
                    }

                    ReadOnlyMemory<byte> data = stream.GetDecodedBytes();
                    if (data.Length > MaxItemBytes)
                    {
                        _warnings.Add("/" + key + " item " + i + " is larger than " + MaxItemBytes + " octets.");
                        continue;
                    }

                    Add(kind, key, i, data, stream.SourceOffset, stream.Reference);
                }
                catch (PdfException e)
                {
                    _warnings.Add("/" + key + " item " + i + " cannot be read: " + e.Message);
                }
            }
        }
    }

    private void Add(int kind, string key, int index, ReadOnlyMemory<byte> data, long offset, PdfReference? reference)
    {
        switch (kind)
        {
            case 0:
                if (Certificate.TryParse(data, out Certificate? c) && c is not null)
                {
                    Certificates.Add(new StoredItem<Certificate>(c, offset, reference));
                    return;
                }

                break;
            case 1:
                if (CertificateRevocationList.TryParse(data, out CertificateRevocationList? l) && l is not null)
                {
                    Crls.Add(new StoredItem<CertificateRevocationList>(l, offset, reference));
                    return;
                }

                break;
            default:
                if (OcspResponse.TryParse(data, out OcspResponse? r) && r is not null)
                {
                    OcspBasicResponse? basic;
                    try
                    {
                        basic = r.BasicResponse;
                    }
                    catch (X509ParseException)
                    {
                        basic = null;
                    }

                    if (basic is not null)
                    {
                        Ocsp.Add(new StoredItem<OcspBasicResponse>(basic, offset, reference));
                        return;
                    }
                }

                break;
        }

        _warnings.Add("/" + key + " item " + index + " does not parse as the object it should be.");
    }
}
