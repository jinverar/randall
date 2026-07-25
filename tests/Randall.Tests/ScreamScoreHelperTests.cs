using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class ScreamScoreHelperTests
{
    [Fact]
    public void IsHot_MatchesHighNoveltyFirstCluster()
    {
        var crash = new CrashSummaryDto(
            Guid.NewGuid(), "p", 1, "havoc", "abc", "input.bin",
            null, null, null, null, null, DateTimeOffset.UtcNow,
            Novelty: 80, OracleScoreTotal: 0, SeenCount: 1);
        Assert.True(ScreamScoreHelper.IsHot(crash));
    }

    [Fact]
    public void GoalReached_WhenMaxScoreMeetsThreshold()
    {
        var crashes = new[]
        {
            new CrashSummaryDto(
                Guid.NewGuid(), "p", 1, "m", "a", "a.bin",
                null, null, null, null, null, DateTimeOffset.UtcNow,
                ScreamScore: 55),
        };
        Assert.True(ScreamScoreHelper.GoalReached(50, crashes));
        Assert.False(ScreamScoreHelper.GoalReached(60, crashes));
    }

    [Fact]
    public void GoalReached_WhenHotCountMeetsThreshold()
    {
        var hot = new CrashSummaryDto(
            Guid.NewGuid(), "p", 1, "m", "a", "a.bin",
            null, null, null, null, null, DateTimeOffset.UtcNow,
            ScreamScore: 30, Novelty: 75, OracleScoreTotal: 50, SeenCount: 1);
        Assert.True(ScreamScoreHelper.GoalReached(1, [hot]));
    }
}
