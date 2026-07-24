using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class FuzzVerboseTests
{
    [Fact]
    public void FuzzConfig_Verbose_DefaultsOff()
    {
        Assert.False(new FuzzConfig().Verbose);
    }

    [Fact]
    public void FuzzRunOptions_Verbose_DefaultsOff()
    {
        Assert.False(new FuzzRunOptions().Verbose);
    }

    [Fact]
    public void HexPreview_RespectsMaxBytes()
    {
        var buf = Enumerable.Range(0, 40).Select(i => (byte)i).ToArray();
        var shortPrev = FuzzAnalystLog.HexPreview(buf, 8);
        var longPrev = FuzzAnalystLog.HexPreview(buf, 32);
        Assert.Contains('…', shortPrev);
        Assert.True(longPrev.Length > shortPrev.Length);
        Assert.StartsWith("00 01 02 03", shortPrev, StringComparison.Ordinal);
    }
}
