using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class CampaignPostmortemEngineTests
{
    [Fact]
    public void Build_Narrative_IncludesStatsAndTeachingPackages()
    {
        var barriers = new List<BarrierItemDto>
        {
            new(
                "barrier-empty-frontier",
                BarrierKind.EmptyFrontier,
                "high",
                "Frontier empty for teaching diagnosis.",
                ["Import coverage layers."]),
        };

        var input = new CampaignPostmortemInput(
            Project: "lab",
            RunId: "run-1",
            Iterations: 200,
            UniqueCrashes: 2,
            CorpusGrowth: 5,
            MutatorRows:
            [
                new MutatorCreditRowDto("havoc", 80, 12, 1, 220, 8),
                new MutatorCreditRowDto("dictionary", 40, 2, 0, 20, 3),
            ],
            Barriers: barriers,
            ScreamFamilies: ["fam-a", "fam-b"],
            StopGoals: new IntelligenceStopGoalProgressDto(
                false, null,
                new Dictionary<string, int> { ["uniqueScreams"] = 1 },
                [new IntelligenceStopGoalItemProgressDto("screams", "Unique screams", 1, 3)]),
            StopReason: null);

        var pm = CampaignPostmortemEngine.Build(input);

        Assert.True(pm.Ok);
        Assert.Equal(200, pm.Iterations);
        Assert.Equal(2, pm.UniqueCrashes);
        Assert.Equal(5, pm.CorpusGrowth);
        Assert.NotEmpty(pm.TopMutators);
        Assert.Contains("havoc", pm.TopMutators[0], StringComparison.OrdinalIgnoreCase);
        Assert.Equal(2, pm.ScreamFamilies.Count);
        Assert.Contains(pm.WhatStalled, w => w.Contains("EmptyFrontier", StringComparison.OrdinalIgnoreCase));
        Assert.NotEmpty(pm.WhatWorked);
        Assert.NotEmpty(pm.WhatStalled);
        Assert.Contains(TeachingPackages.NoWeaponization, pm.NextResearchPackages);
        Assert.Contains(TeachingPackages.RootCauseStudy, pm.NextResearchPackages);
        Assert.DoesNotContain(pm.NarrativeSummary, "shellcode", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(pm.NarrativeSummary, "ROP", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Persist_WritesRunAndLastJson()
    {
        var root = Path.Combine(Path.GetTempPath(), "randfuzz-pm-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var input = new CampaignPostmortemInput(
                Project: "pm-demo",
                RunId: "abc123",
                Iterations: 50,
                UniqueCrashes: 0,
                CorpusGrowth: 0,
                Barriers: [],
                ScreamFamilies: []);

            var pm = CampaignPostmortemEngine.Persist(input, root);
            Assert.True(pm.Ok);

            var last = CampaignPostmortemEngine.LastPath("pm-demo", root);
            Assert.True(File.Exists(last));
            var run = CampaignPostmortemEngine.RunPath("pm-demo", "abc123", root);
            Assert.True(File.Exists(run));

            var loaded = CampaignPostmortemEngine.TryLoadLast("pm-demo", root);
            Assert.NotNull(loaded);
            Assert.Equal(50, loaded!.Iterations);
            Assert.Equal("abc123", loaded.RunId);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Build_StopGoalMet_AppearsInWhatWorked()
    {
        var input = new CampaignPostmortemInput(
            Project: "goals",
            Iterations: 100,
            UniqueCrashes: 1,
            CorpusGrowth: 1,
            Barriers: [],
            StopGoals: new IntelligenceStopGoalProgressDto(
                true, "unique screams threshold",
                new Dictionary<string, int>(),
                []));

        var pm = CampaignPostmortemEngine.Build(input);
        Assert.Contains(pm.WhatWorked, w => w.Contains("Stop goal met", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("Stop", pm.StopGoalSummary ?? "", StringComparison.OrdinalIgnoreCase);
    }
}
