using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class IntelligenceStopGoalTests
{
    private static CrashSummaryDto Crash(
        int score = 0,
        int novelty = 0,
        int oracle = 0,
        int seen = 1,
        string? clusterKey = null) =>
        new(
            Guid.NewGuid(), "test", 1, "havoc", "abc", "input.bin",
            null, null, null, null, null, DateTimeOffset.UtcNow,
            ClusterKey: clusterKey ?? Guid.NewGuid().ToString("N"),
            ScreamScore: score,
            Novelty: novelty,
            OracleScoreTotal: oracle,
            SeenCount: seen);

    [Fact]
    public void Resolve_MapsLegacyScreamScoreGoal()
    {
        var fuzz = new FuzzConfig { ScreamScoreGoal = 55 };
        var goals = IntelligenceStopGoalEvaluator.Resolve(fuzz);
        Assert.Equal(55, goals.LegacyScreamScoreGoal);
        Assert.True(goals.IsEnabled);
    }

    [Fact]
    public void Evaluate_LegacyGoal_WhenMaxScoreMet()
    {
        var goals = new IntelligenceStopGoalsConfig { LegacyScreamScoreGoal = 50 };
        var result = IntelligenceStopGoalEvaluator.Evaluate(goals, [Crash(score: 55)]);
        Assert.True(result.Met);
        Assert.Contains("legacy scream goal", result.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Evaluate_UniqueScoreClusters_WhenCountMet()
    {
        var goals = new IntelligenceStopGoalsConfig
        {
            UniqueScreamsWithScore = new UniqueScreamScoreGoal { Count = 2, MinScore = 50 },
        };
        var crashes = new[]
        {
            Crash(score: 60, clusterKey: "cluster-a"),
            Crash(score: 55, clusterKey: "cluster-b"),
            Crash(score: 30, clusterKey: "cluster-c"),
        };
        var result = IntelligenceStopGoalEvaluator.Evaluate(goals, crashes);
        Assert.True(result.Met);
        Assert.Equal(2, result.Counters["uniqueScoreClusters"]);
        Assert.Contains("unique clusters with score", result.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Evaluate_UniqueScoreClusters_NotMetWhenSameCluster()
    {
        var goals = new IntelligenceStopGoalsConfig
        {
            UniqueScreamsWithScore = new UniqueScreamScoreGoal { Count = 2, MinScore = 50 },
        };
        var crashes = new[]
        {
            Crash(score: 60, clusterKey: "same"),
            Crash(score: 55, clusterKey: "same"),
        };
        var result = IntelligenceStopGoalEvaluator.Evaluate(goals, crashes);
        Assert.False(result.Met);
        Assert.Equal(1, result.Counters["uniqueScoreClusters"]);
    }

    [Fact]
    public void Evaluate_UniqueMomentumFamilies_WhenCountMet()
    {
        var goals = new IntelligenceStopGoalsConfig
        {
            UniqueScreamsWithMomentum = new UniqueScreamMomentumGoal { Count = 2, MinMomentum = 40 },
        };
        var c1 = Crash(score: 50);
        var c2 = Crash(score: 45);
        var c3 = Crash(score: 20);
        var evolutions = new Dictionary<Guid, ScreamEvolutionDto>
        {
            [c1.Id] = new ScreamEvolutionDto(true, c1.Id, "test", "fam-a", null, 1, null, null, 55, "hot",
                ScreamProgressionStep.ControlledAddress, null, 1, [], 1, null, DateTimeOffset.UtcNow),
            [c2.Id] = new ScreamEvolutionDto(true, c2.Id, "test", "fam-b", null, 1, null, null, 42, "warming",
                ScreamProgressionStep.WriteViolation, null, 0, [], 1, null, DateTimeOffset.UtcNow),
            [c3.Id] = new ScreamEvolutionDto(true, c3.Id, "test", "fam-c", null, 1, null, null, 10, "stable",
                ScreamProgressionStep.ReadViolation, null, 0, [], 1, null, DateTimeOffset.UtcNow),
        };
        var result = IntelligenceStopGoalEvaluator.Evaluate(goals, [c1, c2, c3], evolutions);
        Assert.True(result.Met);
        Assert.Equal(2, result.Counters["uniqueMomentumFamilies"]);
    }

    [Fact]
    public void Merge_RunOverridesCampaign()
    {
        var project = new IntelligenceStopGoalsConfig
        {
            UniqueScreamsWithScore = new UniqueScreamScoreGoal { Count = 1, MinScore = 40 },
        };
        var campaign = new IntelligenceStopGoalsConfig
        {
            UniqueScreamsWithScore = new UniqueScreamScoreGoal { Count = 3, MinScore = 55 },
        };
        var run = new IntelligenceStopGoalsConfig
        {
            LegacyScreamScoreGoal = 70,
        };
        var merged = IntelligenceStopGoalEvaluator.Merge(project, campaign, run);
        Assert.Equal(70, merged.LegacyScreamScoreGoal);
        Assert.Equal(3, merged.UniqueScreamsWithScore!.Count);
        Assert.Equal(55, merged.UniqueScreamsWithScore.MinScore);
    }

    [Fact]
    public void Evaluate_ReportsProgressItems_WhenNotMet()
    {
        var goals = new IntelligenceStopGoalsConfig
        {
            UniqueScreamsWithScore = new UniqueScreamScoreGoal { Count = 3, MinScore = 50 },
        };
        var result = IntelligenceStopGoalEvaluator.Evaluate(goals, [Crash(score: 55, clusterKey: "a")]);
        Assert.False(result.Met);
        Assert.Single(result.Items);
        Assert.Equal(1, result.Items[0].Current);
        Assert.Equal(3, result.Items[0].Needed);
    }

    [Fact]
    public void EvaluateCampaign_ScopesClustersPerProject()
    {
        var goals = new IntelligenceStopGoalsConfig
        {
            UniqueScreamsWithScore = new UniqueScreamScoreGoal { Count = 2, MinScore = 40 },
        };
        var root = Path.Combine(Path.GetTempPath(), "randall-stopgoal-" + Guid.NewGuid().ToString("N"));
        try
        {
            foreach (var (project, cluster, score) in new[]
                     {
                         ("proj-a", "shared-key", 50),
                         ("proj-b", "shared-key", 45),
                     })
            {
                var dir = Path.Combine(root, "data", "crashes", project);
                Directory.CreateDirectory(dir);
                var id = Guid.NewGuid();
                File.WriteAllText(Path.Combine(dir, $"{id:N}.json"), "{}");
            }

            var crashesA = new[] { Crash(score: 50, clusterKey: "shared-key") };
            var crashesB = new[] { Crash(score: 45, clusterKey: "shared-key") };
            // Simulate catalog by evaluating merged scoped crashes directly
            var scoped = new[]
            {
                crashesA[0] with { Project = "proj-a", ClusterKey = "proj-a:shared-key" },
                crashesB[0] with { Project = "proj-b", ClusterKey = "proj-b:shared-key" },
            };
            var result = IntelligenceStopGoalEvaluator.Evaluate(goals, scoped);
            Assert.True(result.Met);
            Assert.Equal(2, result.Counters["uniqueScoreClusters"]);
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void MergeForRun_ExcludesCampaignGoals()
    {
        var project = new IntelligenceStopGoalsConfig
        {
            UniqueScreamsWithScore = new UniqueScreamScoreGoal { Count = 1, MinScore = 40 },
        };
        var campaign = new IntelligenceStopGoalsConfig
        {
            UniqueScreamsWithScore = new UniqueScreamScoreGoal { Count = 5, MinScore = 60 },
        };
        var merged = IntelligenceStopGoalEvaluator.MergeForRun(project, null);
        Assert.Equal(1, merged.UniqueScreamsWithScore!.Count);
        Assert.Equal(40, merged.UniqueScreamsWithScore.MinScore);

        var withCampaign = IntelligenceStopGoalEvaluator.Merge(project, campaign, null);
        Assert.Equal(5, withCampaign.UniqueScreamsWithScore!.Count);
    }

    [Fact]
    public void Evaluate_DisabledWhenNoGoals()
    {
        var result = IntelligenceStopGoalEvaluator.Evaluate(new IntelligenceStopGoalsConfig(), [Crash(score: 99)]);
        Assert.False(result.Met);
        Assert.Null(result.Reason);
        Assert.Empty(result.Items);
    }
}
