using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class TargetPlatformGateTests
{
    [Theory]
    [InlineData("randall", "windows", true)]
    [InlineData("randall", "linux", true)]
    [InlineData("aflpp", "windows", false)]
    [InlineData("aflpp", "linux", true)]
    [InlineData("honggfuzz", "windows", false)]
    [InlineData("honggfuzz", "linux", true)]
    [InlineData("afl++", "windows", false)]
    [InlineData("afl++", "linux", true)]
    public void External_engines_runnable_only_on_linux(string engine, string platform, bool expected)
    {
        Assert.Equal(expected, ExternalEngineCampaign.IsRunnableOnPlatform(engine, platform));
    }

    [Fact]
    public void ListTargets_exposes_engine_for_aflpp_harness()
    {
        var afl = CrashCatalog.ListTargets().FirstOrDefault(t =>
            t.Name.Equals("aflpp-harness", StringComparison.OrdinalIgnoreCase));
        Assert.NotNull(afl);
        Assert.Equal(ExternalEngineCampaign.EngineAflpp, afl.Engine);
        Assert.False(ExternalEngineCampaign.IsRunnableOnPlatform(afl.Engine, PlatformScope.Windows));
        Assert.True(ExternalEngineCampaign.IsRunnableOnPlatform(afl.Engine, PlatformScope.Linux));
    }

    [Fact]
    public void ListTargets_stock_profiles_are_randall_engine()
    {
        var targets = CrashCatalog.ListTargets();
        foreach (var name in new[] { "vulnserver", "harness-demo", "file-text", "png-demo" })
        {
            var t = targets.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (t is null) continue; // profile may be absent in sparse checkouts
            Assert.Equal(ExternalEngineCampaign.EngineRandall, t.Engine);
            Assert.True(ExternalEngineCampaign.IsRunnableOnPlatform(t.Engine, PlatformScope.Windows));
        }
    }
}
