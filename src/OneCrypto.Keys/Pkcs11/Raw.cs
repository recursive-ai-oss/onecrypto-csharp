using System.Runtime.InteropServices;

namespace RecursiveAI.OneCrypto.Keys.Pkcs11;

/// <summary>An attribute template (CK_ATTRIBUTE array) whose values sit in one pinned buffer, so the native pointers stay valid for the whole call.</summary>
internal sealed unsafe class Template
{
    private readonly List<(nuint Type, byte[] Value)> _items = [];
    private CkAttribute[]? _native;
    private byte[]? _blob;

    internal int Count => _items.Count;

    internal Template Bool(nuint type, bool value) => Add(type, [value ? (byte)1 : (byte)0]);

    internal Template Ulong(nuint type, nuint value)
    {
        byte[] b = new byte[nuint.Size];
        MemoryMarshal.Write(b, in value);
        return Add(type, b);
    }

    internal Template Text(nuint type, string value) => Add(type, System.Text.Encoding.UTF8.GetBytes(value));

    internal Template Bytes(nuint type, ReadOnlySpan<byte> value) => Add(type, value.ToArray());

    internal Template Add(nuint type, byte[] value)
    {
        _items.Add((type, value));
        _native = null;
        return this;
    }

    /// <summary>The native array; valid while this object is alive. Pointers refer to a pinned buffer.</summary>
    internal CkAttribute[] Native()
    {
        if (_native is not null)
        {
            return _native;
        }

        int total = 0;
        foreach ((_, byte[] v) in _items)
        {
            total += v.Length;
        }

        _blob = GC.AllocateArray<byte>(Math.Max(total, 1), pinned: true);
        byte* basePtr = (byte*)Marshal.UnsafeAddrOfPinnedArrayElement(_blob, 0);
        var native = new CkAttribute[Math.Max(_items.Count, 1)];
        int off = 0;
        for (int i = 0; i < _items.Count; i++)
        {
            byte[] v = _items[i].Value;
            v.CopyTo(_blob, off);
            native[i] = new CkAttribute { Type = _items[i].Type, Value = basePtr + off, Length = (nuint)v.Length };
            off += v.Length;
        }

        return _native = native;
    }
}

/// <summary>The PKCS #11 calls a session makes, each one wrapped so callers see managed arrays and typed exceptions. The caller holds the session lock.</summary>
internal static unsafe class Raw
{
    internal static readonly nuint UnavailableInformation = nuint.MaxValue; // CK_UNAVAILABLE_INFORMATION

    internal static void Check(string function, nuint rv)
    {
        if (rv != 0)
        {
            throw Pkcs11Errors.For(function, rv);
        }
    }

    /// <summary>Reads one attribute; null when the object does not have it or the token will not reveal it (C_GetAttributeValue, §5.7.5).</summary>
    internal static byte[]? GetAttribute(NativeModule m, nuint session, nuint obj, nuint type)
    {
        var a = new CkAttribute { Type = type };
        nuint rv = m.C_GetAttributeValue(session, obj, &a, 1);
        if (rv is (nuint)Pkcs11Result.AttributeSensitive or (nuint)Pkcs11Result.AttributeTypeInvalid)
        {
            return null;
        }

        Check("C_GetAttributeValue", rv);
        if (a.Length == UnavailableInformation)
        {
            return null;
        }

        byte[] value = new byte[(int)a.Length];
        if (value.Length == 0)
        {
            return value;
        }

        fixed (byte* p = value)
        {
            a.Value = p;
            rv = m.C_GetAttributeValue(session, obj, &a, 1);
        }

        Check("C_GetAttributeValue", rv);
        return value;
    }

    /// <summary>Changes one boolean attribute of an object (C_SetAttributeValue, §5.7.6); the token decides whether the object may be modified.</summary>
    internal static void SetBool(NativeModule m, nuint session, nuint obj, nuint type, bool value)
    {
        var t = new Template().Bool(type, value);
        fixed (CkAttribute* a = t.Native())
        {
            Check("C_SetAttributeValue", m.C_SetAttributeValue(session, obj, a, 1));
        }
    }

    internal static nuint[] Find(NativeModule m, nuint session, Template t)
    {
        var found = new List<nuint>();
        fixed (CkAttribute* a = t.Native())
        {
            Check("C_FindObjectsInit", m.C_FindObjectsInit(session, a, (nuint)t.Count));
        }

        try
        {
            nuint* batch = stackalloc nuint[64]; // a fixed small buffer: at most 64 handles per call
            while (true)
            {
                nuint n;
                Check("C_FindObjects", m.C_FindObjects(session, batch, 64, &n));
                for (nuint i = 0; i < n; i++)
                {
                    found.Add(batch[i]);
                }

                if (n < 64)
                {
                    break;
                }
            }
        }
        finally
        {
            _ = m.C_FindObjectsFinal(session);
        }

        return [.. found];
    }

    internal static nuint Create(NativeModule m, nuint session, Template t)
    {
        nuint h;
        fixed (CkAttribute* a = t.Native())
        {
            Check("C_CreateObject", m.C_CreateObject(session, a, (nuint)t.Count, &h));
        }

        return h;
    }

    /// <summary>A one-shot signature (C_SignInit then C_Sign, §5.13).</summary>
    internal static byte[] Sign(NativeModule m, nuint session, nuint key, nuint mechanism, byte[]? parameter, ReadOnlySpan<byte> data, int expected) =>
        OneShot(m, session, key, mechanism, parameter, data, expected, sign: true);

    /// <summary>A one-shot decryption (C_DecryptInit then C_Decrypt, §5.10). The result is plaintext: the caller wipes it.</summary>
    internal static byte[] Decrypt(NativeModule m, nuint session, nuint key, nuint mechanism, byte[]? parameter, ReadOnlySpan<byte> data, int expected) =>
        OneShot(m, session, key, mechanism, parameter, data, expected, sign: false);

    // Both one-shot calls follow the buffer rule of §5.2: a too-small buffer answers CKR_BUFFER_TOO_SMALL with the length needed and keeps the operation active.
    private static byte[] OneShot(NativeModule m, nuint session, nuint key, nuint mechanism, byte[]? parameter, ReadOnlySpan<byte> data, int expected, bool sign)
    {
        fixed (byte* pp = parameter)
        fixed (byte* pd = data)
        {
            var mech = new CkMechanism { Type = mechanism, Parameter = pp, ParameterLength = (nuint)(parameter?.Length ?? 0) };
            Check(sign ? "C_SignInit" : "C_DecryptInit", sign ? m.C_SignInit(session, &mech, key) : m.C_DecryptInit(session, &mech, key));
            return Finish(m, session, pd, (nuint)data.Length, expected, sign);
        }
    }

    private static byte[] Finish(NativeModule m, nuint session, byte* pd, nuint dataLength, int expected, bool sign)
    {
        {
            byte[] buffer = new byte[Math.Max(expected, 1)];
            while (true)
            {
                nuint length = (nuint)buffer.Length;
                nuint rv;
                fixed (byte* po = buffer)
                {
                    rv = sign ? m.C_Sign(session, pd, dataLength, po, &length) : m.C_Decrypt(session, pd, dataLength, po, &length);
                }

                if (rv == (nuint)Pkcs11Result.BufferTooSmall && (int)length > buffer.Length && length < 1 << 20)
                {
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer);
                    buffer = new byte[(int)length];
                    continue;
                }

                try
                {
                    Check(sign ? "C_Sign" : "C_Decrypt", rv);
                    return buffer.AsSpan(0, (int)length).ToArray();
                }
                finally
                {
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer);
                }
            }
        }
    }

    /// <summary>
    /// CKM_EDDSA (v3.1 §6.3.14): CK_EDDSA_PARAMS is {phFlag (CK_BBOOL), ulContextDataLen, pContextData}; pure EdDSA has phFlag false. Ed25519 with no
    /// context takes no parameters at all; Ed448 always gets them.
    /// </summary>
    internal static byte[] SignEddsa(NativeModule m, nuint session, nuint key, ReadOnlySpan<byte> data, ReadOnlySpan<byte> context, bool withParameters, int expected)
    {
        fixed (byte* pc = context)
        fixed (byte* pd = data)
        {
            byte* ep = stackalloc byte[24]; // a fixed small buffer: the three fields of CK_EDDSA_PARAMS on LP64
            new Span<byte>(ep, 24).Clear();
            *(nuint*)(ep + 8) = (nuint)context.Length;
            *(byte**)(ep + 16) = pc;
            var mech = new CkMechanism { Type = 0x1057, Parameter = withParameters ? ep : null, ParameterLength = withParameters ? (nuint)24 : 0 };
            Check("C_SignInit", m.C_SignInit(session, &mech, key));
            return Finish(m, session, pd, (nuint)data.Length, expected, sign: true);
        }
    }

    /// <summary>
    /// CKM_ECDH1_DERIVE with no key derivation function (v3.1 §6.3.17): the secret is the x-coordinate. The peer's public point goes in as the raw
    /// uncompressed point, or as its DER OCTET STRING when <paramref name="point"/> says so. The derived object is a session-only generic secret the
    /// token lets us read; it is read and destroyed here.
    /// </summary>
    internal static byte[] DeriveEcdh(NativeModule m, nuint session, nuint baseKey, ReadOnlySpan<byte> point, int secretLength)
    {
        var t = new Template()
            .Ulong(0x0, 4) // CKA_CLASS = CKO_SECRET_KEY
            .Ulong(0x100, 0x10) // CKA_KEY_TYPE = CKK_GENERIC_SECRET
            .Bool(0x1, false) // CKA_TOKEN: the object lives only in this session
            .Bool(0x103, false) // CKA_SENSITIVE: we must read the value back
            .Bool(0x162, true) // CKA_EXTRACTABLE
            .Ulong(0x161, (nuint)secretLength); // CKA_VALUE_LEN
        nuint handle;
        fixed (byte* pp = point)
        fixed (CkAttribute* a = t.Native())
        {
            byte* ep = stackalloc byte[40]; // CK_ECDH1_DERIVE_PARAMS: kdf, ulSharedDataLen, pSharedData, ulPublicDataLen, pPublicData
            new Span<byte>(ep, 40).Clear();
            *(nuint*)ep = 0x1; // CKD_NULL
            *(nuint*)(ep + 24) = (nuint)point.Length;
            *(byte**)(ep + 32) = pp;
            var mech = new CkMechanism { Type = 0x1050, Parameter = ep, ParameterLength = 40 };
            Check("C_DeriveKey", m.C_DeriveKey(session, &mech, baseKey, a, (nuint)t.Count, &handle));
        }

        try
        {
            return GetAttribute(m, session, handle, 0x11) ?? throw new Pkcs11KeyException("The token would not reveal the derived secret.", "C_GetAttributeValue");
        }
        finally
        {
            _ = m.C_DestroyObject(session, handle);
        }
    }

    /// <summary>C_DeriveKey (§5.18.5): returns the handle of the new object.</summary>
    internal static nuint Derive(NativeModule m, nuint session, nuint baseKey, nuint mechanism, byte[] parameter, Template t)
    {
        fixed (byte* pp = parameter)
        fixed (CkAttribute* a = t.Native())
        {
            var mech = new CkMechanism { Type = mechanism, Parameter = pp, ParameterLength = (nuint)parameter.Length };
            nuint h;
            Check("C_DeriveKey", m.C_DeriveKey(session, &mech, baseKey, a, (nuint)t.Count, &h));
            return h;
        }
    }

    /// <summary>C_GenerateKeyPair (§5.18.2).</summary>
    internal static (nuint Public, nuint Private) GenerateKeyPair(NativeModule m, nuint session, nuint mechanism, Template pub, Template priv)
    {
        fixed (CkAttribute* pa = pub.Native())
        fixed (CkAttribute* qa = priv.Native())
        {
            var mech = new CkMechanism { Type = mechanism };
            nuint a, b;
            Check("C_GenerateKeyPair", m.C_GenerateKeyPair(session, &mech, pa, (nuint)pub.Count, qa, (nuint)priv.Count, &a, &b));
            return (a, b);
        }
    }

    internal static byte[] GetInfo(NativeModule m)
    {
        lock (m.CallGate)
        {
            byte[] info = new byte[96]; // CK_INFO is 88 octets on LP64
            fixed (byte* p = info)
            {
                Check("C_GetInfo", m.C_GetInfo(p));
            }

            return info;
        }
    }

    internal static nuint[] GetSlotList(NativeModule m, bool tokenPresent)
    {
        lock (m.CallGate)
        {
            nuint count = 0;
            Check("C_GetSlotList", m.C_GetSlotList(tokenPresent, null, &count));
            if (count == 0)
            {
                return [];
            }

            nuint[] slots = new nuint[(int)count];
            fixed (nuint* p = slots)
            {
                Check("C_GetSlotList", m.C_GetSlotList(tokenPresent, p, &count));
            }

            return slots.AsSpan(0, (int)count).ToArray();
        }
    }

    internal static byte[] GetSlotInfo(NativeModule m, nuint slot)
    {
        lock (m.CallGate)
        {
            byte[] info = new byte[128]; // CK_SLOT_INFO is 112 octets on LP64
            fixed (byte* p = info)
            {
                Check("C_GetSlotInfo", m.C_GetSlotInfo(slot, p));
            }

            return info;
        }
    }

    internal static byte[] GetTokenInfo(NativeModule m, nuint slot)
    {
        lock (m.CallGate)
        {
            byte[] info = new byte[256]; // CK_TOKEN_INFO is 208 octets on LP64
            fixed (byte* p = info)
            {
                Check("C_GetTokenInfo", m.C_GetTokenInfo(slot, p));
            }

            return info;
        }
    }

    internal static nuint[] GetMechanismList(NativeModule m, nuint slot)
    {
        lock (m.CallGate)
        {
            nuint count = 0;
            Check("C_GetMechanismList", m.C_GetMechanismList(slot, null, &count));
            if (count == 0)
            {
                return [];
            }

            nuint[] list = new nuint[(int)count];
            fixed (nuint* p = list)
            {
                Check("C_GetMechanismList", m.C_GetMechanismList(slot, p, &count));
            }

            return list.AsSpan(0, (int)count).ToArray();
        }
    }

    internal static nuint OpenSession(NativeModule m, nuint slot, nuint flags)
    {
        lock (m.CallGate)
        {
            nuint h;
            Check("C_OpenSession", m.C_OpenSession(slot, flags, &h));
            return h;
        }
    }

    internal static byte[] GetSessionInfo(NativeModule m, nuint session)
    {
        byte[] info = new byte[32]; // CK_SESSION_INFO: slotID, state, flags, ulDeviceError
        fixed (byte* p = info)
        {
            Check("C_GetSessionInfo", m.C_GetSessionInfo(session, p));
        }

        return info;
    }

    /// <summary>C_Login (§5.6.8). A null PIN uses the token's protected authentication path.</summary>
    internal static nuint Login(NativeModule m, nuint session, nuint userType, byte[]? pin)
    {
        fixed (byte* p = pin)
        {
            return m.C_Login(session, userType, p, (nuint)(pin?.Length ?? 0));
        }
    }
}
