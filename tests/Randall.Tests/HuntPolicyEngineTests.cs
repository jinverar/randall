using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Infrastructure.Mutators;
using Xunit;

namespace Randall.Tests;

public class HuntPolicyEngineTests
{
    [Fact]
    public void Evaluate_BoostsWarmingLineage_ModeLineageBreed()
    {
        var signals = new RandallBrain.Signals(
            true,
            "warming",
            null,
            null,
            null,
            [],
            [
                new RandallBrain.ScreamClusterSignal(
                    "fam-write", 72, 55, 3, "parse_buf", false,
                    MomentumScore: 58, MomentumLabel: "warming", Generation: 3,
                    FamilyId: "fam-write", ProgressionStep: ScreamProgressionStep.WriteViolation),
            ]);

        var mutators = BuiltInMutators.Create(["havoc", "splice", "cyclic", "bitflip"], seed: 1);
        var chains = new List<MutatorChainRowDto>
        {
            new(["seed", "havoc", "splice"], 4, 6, 1, 120, 8, "seed→havoc→splice"),
        };

        var policy = HuntPolicyEngine.Evaluate(new HuntPolicyEngine.Context(
            signals, [], chains, mutators, 0.4, 10));

        Assert.Equal(HuntExecutionMode.LineageBreed, policy.Mode);
        Assert.True(policy.HuntValue >= 20);
        Assert.Contains("breed lineage", policy.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(policy.LineageChain);
        Assert.True(policy.LineageChain!.Count >= 2);
    }

    [Fact]
    public void Evaluate_DeprioritizesStagnantNullDeref()
    {
        var signals = new RandallBrain.Signals(
            true,
            "stagnant",
            null,
            null,
            null,
            [],
            [
                new RandallBrain.ScreamClusterSignal(
                    "null-fam", 45, 25, 6, "read_null", false,
                    MomentumScore: 20, ProgressionStep: ScreamProgressionStep.ReadViolation),
            ]);

        var mutators = BuiltInMutators.Create(["havoc", "bitflip"], seed: 2);
        var policy = HuntPolicyEngine.Evaluate(new HuntPolicyEngine.Context(
            signals, [], null, mutators, 0.85, 50, 1.0, 0.1));

        Assert.Contains(policy.Terms, t => t.Label.Contains("null-deref", StringComparison.OrdinalIgnoreCase)
                                           || t.Label.Contains("duplicate", StringComparison.OrdinalIgnoreCase)
                                           || t.Label.Contains("exhaustion", StringComparison.OrdinalIgnoreCase));
        Assert.True(policy.JokerInvokeChance >= 0.1);
    }

    [Fact]
    public void Evaluate_FrontierDominates_HavocExplore()
    {
        var root = Path.Combine(Path.GetTempPath(), "hunt-frontier-" + Guid.NewGuid().ToString("N"));
        try
        {
            const string project = "hunt-frontier";
            WriteFrontier(root, project, score: 82);

            var brain = new RandallBrain();
            var signals = brain.LoadSignals(project, root);
            var mutators = BuiltInMutators.Create(["havoc", "bitflip", "splice"], seed: 3);
            var policy = HuntPolicyEngine.Evaluate(new HuntPolicyEngine.Context(
                signals, [], null, mutators, 0.3, 2));

            Assert.Equal(HuntExecutionMode.HavocExplore, policy.Mode);
            Assert.Equal("havoc", policy.PreferredMutator);
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { /* ignore */ }
        }
    }

    private static void WriteFrontier(string root, string project, int score)
    {
        var dir = Path.Combine(root, "data", "stalk", project);
        Directory.CreateDirectory(dir);
        var report = new FrontierReportDto(
            project,
            DateTimeOffset.UtcNow.ToString("O"),
            "cfg",
            "test frontier",
            4,
            1,
            null,
            [
                new FrontierBranchDto(
                    "bb:0x401000->0x401020",
                    "cfg-branch",
                    score,
                    2,
                    0.4,
                    2,
                    0.6,
                    "parse_input",
                    "0x401000",
                    "0x401020",
                    "demo.exe",
                    "uncovered successor"),
            ],
            "hint");
        File.WriteAllText(
            Path.Combine(dir, FrontierEngine.FileName),
            System.Text.Json.JsonSerializer.Serialize(report));
    }

    [Fact]
    public void ShouldInvokeJoker_RespectsPolicyChance()
    {
        var policy = new HuntPolicyDecision(
            22, HuntExecutionMode.JokerInvoke, "test", JokerInvokeChance: 1.0,
            false, null, [], "baseline", null, 0, null);
        var project = new ProjectConfig { Name = "j", Joker = new JokerConfig { Enabled = false } };
        var rng = new Random(0);
        Assert.True(HuntPolicyEngine.ShouldInvokeJoker(policy, project, rng));
    }

    [Fact]
    public void MutatorCredit_StaleRuns_ReducesSelectionWeight()
    {
        var tracker = new MutatorCreditTracker(persistPath: null, biasEnabled: true);
        for (var i = 0; i < 12; i++)
            tracker.Record("truncate", newEdges: 0, uniqueCrash: false);

        var weight = tracker.GetSelectionWeight("truncate");
        Assert.True(weight <= 2, $"expected low weight, got {weight}");
    }

    [Fact]
    public void PersistAndLoad_RoundTrips()
    {
        var root = Path.Combine(Path.GetTempPath(), "hunt-persist-" + Guid.NewGuid().ToString("N"));
        try
        {
            const string project = "persist-hunt";
            var policy = new HuntPolicyDecision(
                55, HuntExecutionMode.LineageBreed, "test persist", 0.05, false, null,
                [new OracleScoreTerm("crash progression", 12, "warming")],
                "scream", "parse_buf", 60, "splice", ["seed", "splice"]);

            HuntPolicyEngine.PersistLast(policy, project, 99, root);
            var loaded = HuntPolicyEngine.TryLoadSnapshot(project, root);
            Assert.NotNull(loaded);
            Assert.Equal(HuntExecutionMode.LineageBreed, loaded!.Policy.Mode);
            Assert.Equal(55, loaded.Policy.HuntValue);
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { /* ignore */ }
        }
    }
}
