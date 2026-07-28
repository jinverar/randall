using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests.ResearchBenchmark;

public class ResearchBenchmarkTests
{
    [Fact]
    public void Catalog_has_live_and_stub_fixtures()
    {
        Assert.True(ResearchBenchmarkFixtures.Live.Count() >= 3);
        Assert.True(ResearchBenchmarkFixtures.Stubs.Count() >= 3);
        Assert.Equal(8, ResearchBenchmarkFixtures.All.Count);
    }

    [Theory]
    [InlineData("null-deref")]
    [InlineData("ascii-write")]
    [InlineData("av-read")]
    public void Live_fixture_scorecard_passes(string fixtureId)
    {
        var env = ResearchBenchmarkFixtures.All.Single(f => f.FixtureId == fixtureId);
        Assert.False(env.Stub);
        var card = ResearchBenchmarkRunner.Evaluate(env);
        Assert.Equal("PASS", card.Summary);
        Assert.True(card.CrashDetected);
        Assert.True(card.ClassificationOk);
        Assert.True(card.PcOk);
        Assert.True(card.PrimitiveLevelOk);
        Assert.False(card.UnsupportedR5Plus);
        Assert.True(card.ObservedMaturity <= ResearchMaturity.R4);
    }

    [Theory]
    [InlineData("oob-write")]
    [InlineData("integer-trunc")]
    [InlineData("uaf")]
    [InlineData("stack-corrupt")]
    [InlineData("oracle-silent")]
    public void Stub_fixtures_are_marked_todo(string fixtureId)
    {
        var env = ResearchBenchmarkFixtures.All.Single(f => f.FixtureId == fixtureId);
        Assert.True(env.Stub);
        var card = ResearchBenchmarkRunner.Evaluate(env);
        Assert.Equal("STUB — not wired", card.Summary);
    }

    [Fact]
    public void RunAll_reports_live_vs_stub_counts()
    {
        var report = ResearchBenchmarkRunner.RunAll();
        Assert.Equal(3, report.LiveCount);
        Assert.Equal(5, report.StubCount);
        Assert.Equal(report.LiveCount, report.PassedLive);
    }
}
