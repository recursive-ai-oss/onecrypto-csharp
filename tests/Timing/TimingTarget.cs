using System.Security.Cryptography;

namespace OneCrypto.Timing;

/// <summary>Which input class a measurement belongs to. The test asks whether the two classes take the same time.</summary>
public enum TimingClass : byte
{
    /// <summary>The same secret input every time.</summary>
    Fixed = 0,

    /// <summary>A fresh random secret input every time.</summary>
    Random = 1,
}

/// <summary>
/// One operation to time. A primitive registers a target by subclassing this, or with <see cref="FromBytes"/> for the common
/// case of one secret byte string going into one call.
/// </summary>
/// <remarks>
/// The harness calls <see cref="Prepare"/> for a batch, then times <see cref="Run"/> once per index. Everything that allocates
/// or generates randomness belongs in <see cref="Prepare"/>; <see cref="Run"/> must only do the operation under test, must not
/// allocate, and must keep its result alive (for example in a field) so the JIT cannot drop the call.
/// </remarks>
public abstract class TimingTarget
{
    /// <summary>The primitive under test, for example <c>X25519</c>.</summary>
    public abstract string Primitive { get; }

    /// <summary>The operation, for example <c>scalar-multiply</c>.</summary>
    public abstract string Operation { get; }

    /// <summary>
    /// Builds the inputs for one batch. <paramref name="classes"/>[i] says whether input i is the fixed secret or a fresh random
    /// one; the order is random, so Run(i) is called in index order but the classes interleave.
    /// </summary>
    public abstract void Prepare(ReadOnlySpan<TimingClass> classes);

    /// <summary>
    /// Untimed hook the harness calls right before each <see cref="Run"/>, in the same index order. Targets whose secret is a key
    /// build the key object for call <paramref name="index"/> here, so that every call, in either class, runs on a freshly built object
    /// with the same allocation pattern and warmth and only the key value differs. The default does nothing.
    /// </summary>
    public virtual void Before(int index)
    {
    }

    /// <summary>
    /// Fills <paramref name="key"/> for a key-secret call: fresh random bytes, and for the fixed class the fixed key in their place. The
    /// choice is a byte mask, not a branch, so both classes (and the A/A control, whose mask is always zero) execute the same instructions
    /// with the same branch history just before the timed call, and only the key value differs.
    /// </summary>
    protected static void FillKey(Span<byte> key, ReadOnlySpan<byte> fixedKey, TimingClass cls, bool control)
    {
        RandomNumberGenerator.Fill(key);
        byte mask = (byte)(((int)cls - 1) & 0xFF); // Fixed (0) -> 0xFF, Random (1) -> 0x00
        mask &= (byte)(control ? 0 : 0xFF);
        for (int i = 0; i < key.Length; i++)
        {
            key[i] = (byte)((key[i] & ~mask) | (fixedKey[i] & mask));
        }
    }

    /// <summary>
    /// Fills <paramref name="value"/> for a pair test: the first fixed value for the Fixed class, the second for the Random class, blended
    /// by a byte mask so both classes run the same instructions. Each class repeats one value, as the fixed class does in the leak test, so
    /// an effect of seeing the same bytes again and again is in both classes and cancels; a difference that remains is a difference between
    /// the two values.
    /// </summary>
    protected static void FillPair(Span<byte> value, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, TimingClass cls)
    {
        byte mask = (byte)(((int)cls - 1) & 0xFF); // Fixed (0) -> 0xFF, Random (1) -> 0x00
        for (int i = 0; i < value.Length; i++)
        {
            value[i] = (byte)((first[i] & mask) | (second[i] & ~mask));
        }
    }

    /// <summary>Runs the operation on the input prepared for index <paramref name="index"/>. This is the timed call.</summary>
    public abstract void Run(int index);

    /// <summary>
    /// A target whose secret is one byte string of <paramref name="secretLength"/> bytes. The fixed class reuses one random
    /// value for the whole run (or <paramref name="fixedSecret"/>, when the operation needs the fixed class to hit a particular value,
    /// such as a compare against a known reference); the random class draws a new one per call. <paramref name="run"/> receives the secret.
    /// </summary>
    public static TimingTarget FromBytes(string primitive, string operation, int secretLength, Action<byte[]> run, byte[]? fixedSecret = null, bool control = false, bool pair = false) =>
        new BytesTarget(primitive, operation, secretLength, run, fixedSecret, control, pair);

    private sealed class BytesTarget(string primitive, string operation, int length, Action<byte[]> run, byte[]? fixedSecret, bool control, bool pair) : TimingTarget
    {
        private readonly byte[] _fixed = fixedSecret ?? RandomNumberGenerator.GetBytes(length);
        private readonly byte[] _other = RandomNumberGenerator.GetBytes(length);
        private byte[][] _inputs = [];

        public override string Primitive => primitive;

        public override string Operation => operation;

        public override void Prepare(ReadOnlySpan<TimingClass> classes)
        {
            if (_inputs.Length < classes.Length)
            {
                _inputs = new byte[classes.Length][];
                for (int i = 0; i < _inputs.Length; i++)
                {
                    _inputs[i] = new byte[length];
                }
            }

            // Both classes run the same instructions: fresh random bytes, then the fixed value blended in by a byte mask. A class-dependent
            // copy-or-fill would leave the two classes' inputs in different cache and predictor states before the timed call. The control
            // (mask zero) makes both classes random.
            for (int i = 0; i < classes.Length; i++)
            {
                if (pair)
                {
                    FillPair(_inputs[i], _fixed, _other, classes[i]);
                }
                else
                {
                    FillKey(_inputs[i], _fixed, classes[i], control);
                }
            }
        }

        public override void Run(int index) => run(_inputs[index]);
    }
}
