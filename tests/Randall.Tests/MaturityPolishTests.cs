using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Infrastructure.BugHunt;
using Xunit;

namespace Randall.Tests;

public class LabAccessTests
{
    [Theory]
    [InlineData("0.0.0.0", true)]
    [InlineData("*", true)]
    [InlineData("::", true)]
    [InlineData("[::]", true)]
    [InlineData("127.0.0.1", false)]
    [InlineData("localhost", false)]
    [InlineData(null, false)]
    public void NonLoopbackBindDetection(string? bind, bool expected) =>
        Assert.Equal(expected, LabAccess.IsNonLoopbackBind(bind));

    [Fact]
    public void MatchesConfigured_OpenWhenUnset()
    {
        var prev = Environment.GetEnvironmentVariable(LabAccess.EnvToken);
        try
        {
            Environment.SetEnvironmentVariable(LabAccess.EnvToken, null);
            Assert.True(LabAccess.MatchesConfigured(["anything"]));
        }
        finally
        {
            Environment.SetEnvironmentVariable(LabAccess.EnvToken, prev);
        }
    }

    [Fact]
    public void MatchesConfigured_RequiresExactToken()
    {
        var prev = Environment.GetEnvironmentVariable(LabAccess.EnvToken);
        try
        {
            Environment.SetEnvironmentVariable(LabAccess.EnvToken, "lab-secret");
            Assert.True(LabAccess.MatchesConfigured(["lab-secret"]));
            Assert.False(LabAccess.MatchesConfigured(["wrong"]));
            Assert.False(LabAccess.MatchesConfigured([null, ""]));
        }
        finally
        {
            Environment.SetEnvironmentVariable(LabAccess.EnvToken, prev);
        }
    }
}

public class ExecutableResolverTests
{
    [Fact]
    public void Candidates_AddExeOnWindowsOrStripOnUnix()
    {
        var bare = ExecutableResolver.Candidates("targets/reeldeck/reeldeck").ToList();
        var exe = ExecutableResolver.Candidates("targets/vulnserver/randall-vulnserver.exe").ToList();
        if (OperatingSystem.IsWindows())
        {
            Assert.Contains("targets/reeldeck/reeldeck.exe", bare);
            Assert.Empty(exe); // already has .exe — no alternate required
        }
        else
        {
            Assert.Empty(bare);
            Assert.Contains("targets/vulnserver/randall-vulnserver", exe);
        }
    }
}

public class BugHunterAttributionTests
{
    [Fact]
    public void ConfidenceTier_AnnotationHigh_StyleLow()
    {
        var annotated = new BugHunterBlockDto(
            "a.c", 1, 10, "c", BugHunterProvenance.AnnotatedAi, 0.95,
            ["annotation:BEGIN AI"], "x");
        var style = new BugHunterBlockDto(
            "b.c", 1, 80, "c", BugHunterProvenance.LikelyAi, 0.5,
            ["style:high-comment-ratio"], "y");
        var tool = new BugHunterBlockDto(
            "c.ts", 1, 20, "ts", BugHunterProvenance.LikelyAi, 0.7,
            ["tool:copilot"], "z");

        Assert.Equal("high", BugHunterAttribution.ConfidenceTier(annotated));
        Assert.Equal("low", BugHunterAttribution.ConfidenceTier(style));
        Assert.Equal("medium", BugHunterAttribution.ConfidenceTier(tool));
    }

    [Fact]
    public void ToMarkdown_IncludesTiersAndLimitations()
    {
        var scan = new BugHunterScanDto(
            "/tmp/src", 1, 1, 0, 0,
            [
                new BugHunterBlockDto(
                    "a.c", 1, 5, "c", BugHunterProvenance.AnnotatedAi, 0.9,
                    ["annotation:BEGIN AI"], "preview"),
            ],
            [], [], DateTimeOffset.UtcNow);
        var md = BugHunterAttribution.ToMarkdown(scan);
        Assert.Contains("Confidence tiers", md);
        Assert.Contains("Limitations", md);
        Assert.Contains("| high |", md);
    }
}

public class PathCoverageSetTests
{
    [Fact]
    public void Add_TracksNoveltyAndPersists()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-pathcov-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var state = Path.Combine(dir, "paths.txt");
            var set = new PathCoverageSet(state);
            set.Load();
            Assert.Equal(2, set.Add(["parse_header", "decode_mad"]));
            Assert.Equal(0, set.Add(["parse_header"]));
            Assert.Equal(1, set.Add(["studio_export"]));
            Assert.Equal(3, set.Total);

            var again = new PathCoverageSet(state);
            again.Load();
            Assert.Equal(3, again.Total);
            Assert.Equal(0, again.Add(["decode_mad"]));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best-effort */ }
        }
    }
}
