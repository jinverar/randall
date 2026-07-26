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
            true, "warming", null, null, null, [],
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
            true, "stagnant", null, null, null, [],
            [
                new RandallBrain.ScreamClusterSignal(
                    "null-fam", 45, 25, 6, "read_null", false,
                    MomentumScore: 20, ProgressionStep: ScreamProgressionStep.ReadViolation),
            ]);

        var mutators = BuiltInMutators.Create(["havoc", "bitflip"], seed: 2);
        var policy = HuntPolicyEngine.Evaluate(new HuntPolicyEngine.Context(
            signals, [], null, mutators, 0.85, 50, 1.0, 0.1));

        Assert.Contains(policy.Terms, t =>
            t.Label.Contains("null-deref", StringComparison.OrdinalIgnoreCase)
            || t.Label.Contains("duplicate", StringComparison.OrdinalIgnoreCase)
            || t.Label.Contains("exhaustion", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(policy.Actions ?? [], a => a.Kind == HuntPolicyActionKind.Deprioritize);
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
                signals, [], null, mutators, 0.3, 2, Project: project, RepoRoot: root));

            Assert.Equal(HuntExecutionMode.HavocExplore, policy.Mode);
            Assert.Equal("havoc", policy.PreferredMutator);
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void ShouldInvokeJoker_RespectsPolicyChance()
    {
        var policy = new HuntPolicyDecision(
            22, HuntExecutionMode.JokerInvoke, "test", JokerInvokeChance: 1.0,
            false, null, [], "baseline", null, 0, null);
        var project = new ProjectConfig { Name = "j", Joker = new JokerConfig { Enabled = false } };
        Assert.True(HuntPolicyEngine.ShouldInvokeJoker(policy, project, new Random(0)));
    }

    [Fact]
    public void MutatorCredit_StaleRuns_ReducesSelectionWeight()
    {
        var tracker = new MutatorCreditTracker(persistPath: null, biasEnabled: true);
        for (var i = 0; i < 12; i++)
            tracker.Record("truncate", newEdges: 0, uniqueCrash: false);

        var weight = tracker.GetSelectionWeight("truncate");
        Assert.True(weight <= 2, $"expected low weight, got {weight}");
        Assert.True(weight >= MutatorCreditTracker.MinSelectionWeightFloor);
    }

    [Fact]
    public void MutatorCredit_ChronicFailure_NeverBelowFloor()
    {
        var tracker = new MutatorCreditTracker(persistPath: null, biasEnabled: true);
        for (var i = 0; i < 30; i++)
            tracker.Record("deadweight", newEdges: 0, uniqueCrash: false);

        Assert.Equal(MutatorCreditTracker.MinSelectionWeightFloor, tracker.GetSelectionWeight("deadweight"));
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
                "scream", "parse_buf", 60, "splice", ["seed", "splice"],
                Actions: [new HuntPolicyAction(HuntPolicyActionKind.Boost, "scream:warming", "test")]);

            HuntPolicyEngine.PersistLast(policy, project, 99, root);
            var loaded = HuntPolicyEngine.TryLoadSnapshot(project, root);
            Assert.NotNull(loaded);
            Assert.Equal(HuntExecutionMode.LineageBreed, loaded!.Policy.Mode);
            Assert.Equal(55, loaded.Policy.HuntValue);
            Assert.Single(loaded.Policy.Actions!);
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void AdaptWeights_ClampedToBounds()
    {
        var root = Path.Combine(Path.GetTempPath(), "hunt-weights-" + Guid.NewGuid().ToString("N"));
        try
        {
            const string project = "weight-bounds";
            var policy = new HuntPolicyDecision(
                70, HuntExecutionMode.LineageBreed, "test", 0, false, null,
                [
                    new OracleScoreTerm("crash progression", 20, "scream"),
                    new OracleScoreTerm("target gravity", 15, "gravity"),
                ],
                "scream", "fam", 70, "splice");

            for (var i = 1; i <= HuntPolicyEngine.FeedbackInterval; i++)
                HuntPolicyEngine.PersistLast(policy, project, i, root, observedNewEdges: 3);

            var weights = HuntPolicyEngine.LoadOrCreateWeights(project, root);
            Assert.InRange(weights.Weights.Scream, HuntPolicyTermWeights.Min, HuntPolicyTermWeights.Max);
            Assert.InRange(weights.Weights.Gravity, HuntPolicyTermWeights.Min, HuntPolicyTermWeights.Max);
            Assert.Equal(HuntPolicyEngine.FeedbackInterval, weights.LastAdaptIteration);
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void ModeHysteresis_HoldsLineageBreed_OverJokerFlip()
    {
        var signals = new RandallBrain.Signals(
            true, "mixed", null, null, null, [],
            [
                new RandallBrain.ScreamClusterSignal(
                    "fam-warm", 50, 40, 2, "parse", false,
                    MomentumScore: 42, MomentumLabel: "warming", Generation: 2, FamilyId: "fam-warm"),
                new RandallBrain.ScreamClusterSignal(
                    "null-a", 40, 20, 5, "read", false,
                    ProgressionStep: ScreamProgressionStep.ReadViolation),
                new RandallBrain.ScreamClusterSignal(
                    "null-b", 38, 18, 4, "read2", true),
            ]);

        var mutators = BuiltInMutators.Create(["havoc"], seed: 4);
        var actions = new List<HuntPolicyAction>();
        var mode = HuntPolicyEngine.ApplyModeHysteresis(
            HuntExecutionMode.JokerInvoke,
            HuntExecutionMode.LineageBreed,
            new HuntPolicyEngine.Context(signals, [], null, mutators, 0.6, 50),
            huntValue: 25,
            warming: signals.ScreamClusters.Where(s => s.MomentumScore >= 40).ToList(),
            stagnantNull: 1,
            actions);

        Assert.Equal(HuntExecutionMode.LineageBreed, mode);
        Assert.Contains(actions, a => a.Kind == HuntPolicyActionKind.Hold);
    }

    [Fact]
    public void Evaluate_GravityReport_AddsGravityTerms()
    {
        var root = Path.Combine(Path.GetTempPath(), "hunt-gravity-" + Guid.NewGuid().ToString("N"));
        try
        {
            const string project = "hunt-gravity";
            WriteGravity(root, project, aggregate: 62, wellScore: 72, label: "strcpy_sink");

            var brain = new RandallBrain();
            var signals = brain.LoadSignals(project, root);
            var mutators = BuiltInMutators.Create(["havoc", "dictionary"], seed: 5);
            var policy = HuntPolicyEngine.Evaluate(new HuntPolicyEngine.Context(
                signals, [], null, mutators, 0.2, 5, Project: project, RepoRoot: root));

            Assert.Contains(policy.Terms, t =>
                t.Label.Contains("gravity", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(policy.Actions ?? [],
                a => a.Kind == HuntPolicyActionKind.Boost
                     && a.Target.Contains("gravity", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Evaluate_LowRoiMutator_EmitsReduceAction()
    {
        var signals = new RandallBrain.Signals(
            true, "mut", null, null, null, [],
            [new RandallBrain.ScreamClusterSignal("seed-fam", 45, 35, 1, "parse", false)]);
        var mutators = BuiltInMutators.Create(["truncate", "havoc"], seed: 6);
        var rows = new List<MutatorCreditRowDto>
        {
            new("truncate", 20, 0, 0, 0, 1, StaleRuns: 8, FailureRate: 0.92),
        };

        var policy = HuntPolicyEngine.Evaluate(new HuntPolicyEngine.Context(
            signals, rows, null, mutators, 0.5, 10));

        Assert.Contains(policy.Actions ?? [],
            a => a.Kind is HuntPolicyActionKind.Reduce or HuntPolicyActionKind.Deprioritize
                 && a.Target.Contains("truncate", StringComparison.OrdinalIgnoreCase));
    }

    private static void WriteFrontier(string root, string project, int score)
    {
        var dir = Path.Combine(root, "data", "stalk", project);
        Directory.CreateDirectory(dir);
        var report = new FrontierReportDto(
            project, DateTimeOffset.UtcNow.ToString("O"), "cfg", "test frontier", 4, 1, null,
            [
                new FrontierBranchDto(
                    "bb:0x401000->0x401020", "cfg-branch", score, 2, 0.4, 2, 0.6,
                    "parse_input", "0x401000", "0x401020", "demo.exe", "uncovered successor"),
            ],
            "hint");
        File.WriteAllText(Path.Combine(dir, FrontierEngine.FileName),
            System.Text.Json.JsonSerializer.Serialize(report));
    }

    private static void WriteGravity(string root, string project, int aggregate, int wellScore, string label)
    {
        var dir = Path.Combine(root, "data", "stalk", project);
        Directory.CreateDirectory(dir);
        TargetGravityEngine.Save(new TargetGravityReportDto(
            project, DateTimeOffset.UtcNow.ToString("O"), "cfg", "test gravity", 10, 1, aggregate,
            [
                new TargetGravityWellDto(
                    "sink:strcpy:parse", "ghidra-dangerous", wellScore, 80, 0.9, 2,
                    "parse_input", "0x401100", label, "Ghidra sink toward strcpy"),
            ],
            "hint",
            [new TargetGravityTopSnapshotDto("sink:strcpy:parse", wellScore, label, "test")]), root);
    }
}
