using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using RecursiveAI.OneCrypto.Keys.Pkcs11;

namespace OneCrypto.Keys.Tests;

/// <summary>
/// A module that lies about lengths and counts: the backend must answer with a typed error, never read or allocate past what it asked for,
/// and never loop without end. The module is a table of native-callable functions that answer from a script.
/// </summary>
public unsafe class HostilePkcs11ModuleTests
{
    private static nuint s_findCount, s_attributeLength, s_slotCount, s_signLength, s_signRv, s_signCalls;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static nuint FindInit(nuint session, CkAttribute* template, nuint count) => 0;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static nuint FindFinal(nuint session) => 0;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static nuint Find(nuint session, nuint* handles, nuint max, nuint* found)
    {
        *found = s_findCount;
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static nuint GetAttribute(nuint session, nuint handle, CkAttribute* template, nuint count)
    {
        template->Length = s_attributeLength;
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static nuint SlotList(byte present, nuint* slots, nuint* count)
    {
        *count = s_slotCount;
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static nuint SignInit(nuint session, CkMechanism* mechanism, nuint key) => 0;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static nuint Sign(nuint session, byte* input, nuint inputLength, byte* output, nuint* outputLength)
    {
        s_signCalls++;
        *outputLength = s_signLength;
        return s_signRv;
    }

    private static NativeModule Module()
    {
        var f = new nint[NativeModule.Slots.Count];
        f[NativeModule.Slots.FindObjectsInit] = (nint)(delegate* unmanaged[Cdecl]<nuint, CkAttribute*, nuint, nuint>)&FindInit;
        f[NativeModule.Slots.FindObjectsFinal] = (nint)(delegate* unmanaged[Cdecl]<nuint, nuint>)&FindFinal;
        f[NativeModule.Slots.FindObjects] = (nint)(delegate* unmanaged[Cdecl]<nuint, nuint*, nuint, nuint*, nuint>)&Find;
        f[NativeModule.Slots.GetAttributeValue] = (nint)(delegate* unmanaged[Cdecl]<nuint, nuint, CkAttribute*, nuint, nuint>)&GetAttribute;
        f[NativeModule.Slots.GetSlotList] = (nint)(delegate* unmanaged[Cdecl]<byte, nuint*, nuint*, nuint>)&SlotList;
        f[NativeModule.Slots.SignInit] = (nint)(delegate* unmanaged[Cdecl]<nuint, CkMechanism*, nuint, nuint>)&SignInit;
        f[NativeModule.Slots.Sign] = (nint)(delegate* unmanaged[Cdecl]<nuint, byte*, nuint, byte*, nuint*, nuint>)&Sign;
        return NativeModule.ForFunctions(f);
    }

    [Fact]
    public void AFindResultLargerThanTheBatchIsRefusedBeforeItIsRead()
    {
        NativeModule m = Module();
        s_findCount = 1000; // the buffer holds 64 handles; reading 1000 would run off the stack
        Pkcs11Exception e = Assert.Throws<Pkcs11Exception>(() => Raw.Find(m, 1, new Template()));
        Assert.Equal("C_FindObjects", e.Function);
    }

    [Fact]
    public void AModuleThatNeverStopsFindingIsStopped()
    {
        NativeModule m = Module();
        s_findCount = Raw.FindBatch; // a full batch every time
        Assert.Throws<Pkcs11Exception>(() => Raw.Find(m, 1, new Template()));
    }

    [Theory]
    [InlineData(0x7FFFFFFFUL)]
    [InlineData(0xFFFFFFFEUL)]
    [InlineData(0x1_0000_0000UL)]
    [InlineData(ulong.MaxValue - 1)]
    public void AnAttributeOfAnImpossibleSizeIsRefusedBeforeAllocation(ulong length)
    {
        NativeModule m = Module();
        s_attributeLength = (nuint)length;
        Assert.Throws<Pkcs11Exception>(() => Raw.GetAttribute(m, 1, 2, 0x11));
    }

    [Fact]
    public void ASlotListCountAboveTheLimitIsRefused()
    {
        NativeModule m = Module();
        s_slotCount = 1_000_000_000;
        Assert.Throws<Pkcs11Exception>(() => Raw.GetSlotList(m, true));
    }

    [Fact]
    public void ALengthLargerThanTheOutputBufferIsATypedError()
    {
        NativeModule m = Module();
        s_signRv = 0;
        s_signLength = 100_000;
        Assert.Throws<Pkcs11Exception>(() => Raw.Sign(m, 1, 2, 3, null, new byte[32], 256));
    }

    [Fact]
    public void AModuleThatKeepsAskingForABiggerBufferIsAskedOnce()
    {
        NativeModule m = Module();
        s_signRv = (nuint)Pkcs11Result.BufferTooSmall;
        s_signLength = 1024;
        s_signCalls = 0;
        Assert.Throws<Pkcs11Exception>(() => Raw.Sign(m, 1, 2, 3, null, new byte[32], 256));
        Assert.True(s_signCalls <= 2, $"{s_signCalls} calls");
    }
}
