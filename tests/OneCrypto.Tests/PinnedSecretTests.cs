using RecursiveAI.OneCrypto.Internal;

namespace OneCrypto.Tests;

public class PinnedSecretTests
{
    [Fact]
    public void HoldsBytesAndZeroesThemOnDispose()
    {
        var s = new PinnedSecret([1, 2, 3]);
        Span<byte> view = s.Span;
        Assert.Equal(3, s.Length);
        Assert.True(s.ReadOnlySpan.SequenceEqual(new byte[] { 1, 2, 3 }));
        s.Dispose();
        Assert.True(view.SequenceEqual(new byte[3]), "the buffer is zero after Dispose");
        Assert.Throws<ObjectDisposedException>(() => s.Length);
        s.Dispose();
    }
}
