using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// The full 64 x 64 -> 128-bit product for the field and scalar arithmetic. <c>Math.BigMul(a, b, out low)</c> makes the JIT keep
/// the low word in memory (it takes the address of the local), which costs a store and a load per product in the long
/// multiply chains; asking for the high word through the hardware multiply and computing the low word as a plain product keeps
/// everything in registers. Every path is constant time: the multiply instructions take the same time for every operand.
/// </summary>
internal static class WideMul
{
    /// <summary>The high 64 bits of a·b.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong High(ulong a, ulong b)
    {
        // The ISA checks are JIT-time constants: only the branch for this machine is compiled.
        if (Bmi2.X64.IsSupported)
        {
            return Bmi2.X64.MultiplyNoFlags(a, b);
        }
        if (ArmBase.Arm64.IsSupported)
        {
            return ArmBase.Arm64.MultiplyHigh(a, b);
        }
        return Math.BigMul(a, b, out _);
    }
}
