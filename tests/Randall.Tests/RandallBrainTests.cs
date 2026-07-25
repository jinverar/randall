using System.Text.Json;
using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Infrastructure.Mutators;
using Xunit;

namespace Randall.Tests;

public class RandallBrainTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    [Fact]
    public void ShouldActivate_WhenFrontierExists()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "brain-frontier";
            WriteFrontier(root, project, score: 72);

            var brain = new RandallBrain();
            var signals = brain.LoadSignals(project, root);
            var projectCfg = new ProjectConfig { Name = project, Fuzz = new FuzzConfig { Brain = true } };

            Assert.True(signals.HasData);
            Assert.True(RandallBrain.ShouldActivate(projectCfg, signals));
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void Decide_PrefersFrontier_WithExplainableTerms()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "brain-pick";
            WriteFrontier(root, project, score: 88);
            WriteStaticMap(root, project, fuzzPriority: 55);

            var brain = new RandallBrain();
            var signals = brain.LoadSignals(project, root);
            var mutators = BuiltInMutators.Create(
                ["bitflip", "havoc", "dictionary", "splice", "cyclic"], seed: 42);
            var decision = brain.Decide(project, signals, [], mutators, iteration: 3);

            Assert.True(decision.Active);
            Assert.Equal("frontier", decision.FocusKind);
            Assert.Contains("frontier rank", decision.WhyTerms[0].Label, StringComparison.OrdinalIgnoreCase);
            Assert.True(decision.CorpusPriorityBias >= 0.78);
            Assert.True(decision.RecommendedEnergyBoost >= 3);
            Assert.Contains("Randall thinks:", decision.Summary, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void Decide_StaticMap_PrefersDictionaryMutator()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "brain-static";
            WriteStaticMap(root, project, fuzzPriority: 91);

            var brain = new RandallBrain();
            var signals = brain.LoadSignals(project, root);
            var mutators = BuiltInMutators.Create(
                ["bitflip", "havoc", "dictionary", "splice", "cyclic"], seed: 42);
            var decision = brain.Decide(project, signals, [], mutators, iteration: 1);

            Assert.True(decision.Active);
            Assert.Equal("static", decision.FocusKind);
            Assert.Equal("dictionary", decision.PreferredMutator);
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void Decide_SaturatedScreamClusters_DeprioritizedInTerms()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "brain-scream";
            WriteFrontier(root, project, score: 40);

            var signals = new RandallBrain.Signals(
                true,
                "test",
                FrontierEngine.TryLoad(project, root),
                null,
                null,
                [],
                [
                    new RandallBrain.ScreamClusterSignal("cluster-a", 80, 20, 12, "crash_fn", Saturated: true),
                    new RandallBrain.ScreamClusterSignal("cluster-a", 80, 20, 12, "crash_fn", Saturated: true),
                ]);

            var brain = new RandallBrain();
            var mutators = BuiltInMutators.Create(
                ["bitflip", "havoc", "dictionary", "splice", "cyclic"], seed: 42);
            var decision = brain.Decide(project, signals, [], mutators, iteration: 5);

            Assert.Contains(decision.WhyTerms, t =>
                t.Label.Contains("saturation", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void PickMutator_BlendsBrainPreferenceWithCredit()
    {
        var mutators = BuiltInMutators.Create(
            ["bitflip", "havoc", "dictionary"], seed: 7);
        var credit = new MutatorCreditTracker(persistPath: null, biasEnabled: true);
        credit.Record("bitflip", 5, uniqueCrash: false);
        credit.Record("bitflip", 5, uniqueCrash: false);
        credit.Record("havoc", 0, uniqueCrash: false);

        var decision = new NextHuntDecision(
            1,
            DateTimeOffset.UtcNow,
            "demo",
            true,
            "test",
            "frontier",
            "door",
            80,
            "dictionary",
            0.8,
            4,
            [new OracleScoreTerm("frontier rank", 80, "cfg")],
            new OracleScore(80, [], ""));

        var brain = new RandallBrain();
        var picks = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < 200; i++)
        {
            var pick = brain.PickMutator(decision, mutators, credit, Random.Shared);
            picks[pick.Name] = picks.GetValueOrDefault(pick.Name) + 1;
        }

        Assert.True(picks.GetValueOrDefault("dictionary") > 40);
    }

    [Fact]
    public void PersistLast_WritesBrainJson()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "brain-persist";
            var brain = new RandallBrain();
            var decision = new NextHuntDecision(
                9,
                DateTimeOffset.UtcNow,
                project,
                true,
                "Randall thinks: frontier door [70]",
                "frontier",
                "door",
                70,
                "havoc",
                0.82,
                4,
                [new OracleScoreTerm("frontier rank", 70, "cfg")],
                new OracleScore(70, [new OracleScoreTerm("frontier rank", 70, "cfg")], "cfg"));

            brain.PersistLast(decision, root);

            var path = RandallBrain.LastDecisionPath(project, root);
            Assert.True(File.Exists(path));
            var loaded = RandallBrain.TryLoadSnapshot(project, root);
            Assert.NotNull(loaded?.LastDecision);
            Assert.Equal("frontier", loaded.LastDecision!.FocusKind);
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void ShouldActivate_FalseWhenBrainDisabled()
    {
        var signals = new RandallBrain.Signals(true, "x", null, null, null, [], []);
        var projectCfg = new ProjectConfig { Name = "x", Fuzz = new FuzzConfig { Brain = false } };
        Assert.False(RandallBrain.ShouldActivate(projectCfg, signals));
    }

    [Fact]
    public void Decide_RichFrontier_BeatsHighStaticPriority()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "brain-rich-frontier";
            WriteRichFrontier(root, project, count: 8, topScore: 82);
            WriteStaticMap(root, project, fuzzPriority: 78);

            var brain = new RandallBrain();
            var signals = brain.LoadSignals(project, root);
            var mutators = BuiltInMutators.Create(
                ["bitflip", "havoc", "dictionary", "splice", "cyclic"], seed: 42);
            var decision = brain.Decide(project, signals, [], mutators, iteration: 2);

            Assert.True(decision.Active);
            Assert.Equal("frontier", decision.FocusKind);
            Assert.True(decision.CorpusPriorityBias >= 0.84);
            Assert.Contains(decision.WhyTerms, t =>
                t.Label.Contains("frontier", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void ToRandallDecision_MapsReviewerShape()
    {
        var decision = new NextHuntDecision(
            12,
            DateTimeOffset.UtcNow,
            "demo",
            true,
            "Randall thinks: frontier door [88]",
            "frontier",
            "parse_input→0x401020",
            88,
            "havoc",
            0.86,
            5,
            [
                new OracleScoreTerm("frontier rank", 75, "cfg-branch"),
                new OracleScoreTerm("frontier richness", 10, "boosted"),
                new OracleScoreTerm("mutator pick", 6, "havoc"),
            ],
            new OracleScore(91, [], "cfg"));

        var mapped = decision.ToRandallDecision();

        Assert.Equal("frontier:parse_input→0x401020", mapped.InputId);
        Assert.Equal(91, mapped.Score);
        Assert.True(mapped.Reasons.ContainsKey("frontierProximity"));
        Assert.Equal("havoc", mapped.Actions.PreferredMutator);
        Assert.Equal("parse_input→0x401020", mapped.Actions.TargetFunction);
        Assert.True(mapped.Actions.EnergyMultiplier >= 2.0);
        Assert.True(mapped.Actions.RetainFocus);
    }

    [Fact]
    public void PersistLast_IncludesDecisionAlias()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "brain-alias";
            var brain = new RandallBrain();
            var decision = new NextHuntDecision(
                3,
                DateTimeOffset.UtcNow,
                project,
                true,
                "Randall thinks: static parse [80]",
                "static",
                "parse_input",
                80,
                "dictionary",
                0.78,
                3,
                [new OracleScoreTerm("fuzz priority", 80, "80/100")],
                new OracleScore(80, [new OracleScoreTerm("fuzz priority", 80, "80/100")], "static"));

            brain.PersistLast(decision, root);

            var json = File.ReadAllText(RandallBrain.LastDecisionPath(project, root));
            Assert.Contains("\"decision\"", json, StringComparison.Ordinal);
            Assert.Contains("\"inputId\"", json, StringComparison.Ordinal);
            Assert.Contains("\"actions\"", json, StringComparison.Ordinal);
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void PersistFocus_WritesBrainFocusJson()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "brain-focus-persist";
            var focus = RandallBrain.PersistFocus(
                project,
                "frontier",
                "Unopened door → 0x401020",
                "0x401020",
                root);

            var path = RandallBrain.FocusPath(project, root);
            Assert.True(File.Exists(path));
            var loaded = RandallBrain.TryLoadFocus(project, root);
            Assert.NotNull(loaded);
            Assert.Equal("frontier", loaded!.FocusKind);
            Assert.Equal("Unopened door → 0x401020", loaded.FocusLabel);
            Assert.Equal("0x401020", loaded.Address);
            Assert.Equal(focus.SetAt, loaded.SetAt);
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void Decide_PrefersPinnedFocus()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "brain-focus-decide";
            WriteFrontier(root, project, score: 55);
            WriteStaticMap(root, project, fuzzPriority: 91);
            RandallBrain.PersistFocus(
                project,
                "frontier",
                "parse_input → 0x401020",
                "0x401020",
                root);

            var brain = new RandallBrain();
            var signals = brain.LoadSignals(project, root);
            var mutators = BuiltInMutators.Create(
                ["bitflip", "havoc", "dictionary", "splice", "cyclic"], seed: 42);
            var decision = brain.Decide(project, signals, [], mutators, iteration: 4, root);

            Assert.True(decision.Active);
            Assert.Equal("frontier", decision.FocusKind);
            Assert.Contains("0x401020", decision.FocusLabel ?? "", StringComparison.OrdinalIgnoreCase);
            Assert.Contains(decision.WhyTerms, t =>
                t.Label.Contains("pinned focus", StringComparison.OrdinalIgnoreCase));
            Assert.True(
                decision.Summary.Contains("pinned focus", StringComparison.OrdinalIgnoreCase),
                decision.Summary);
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void SortFactoryMap_AlmostOpenedWhenApproachCrossedExist()
    {
        var targets = new List<StalkIntelligenceTargetDto>
        {
            new("f:low", "frontier", "door-low", 90, "", "0x1", null, null, 2, 1),
            new("f:high", "frontier", "door-high", 40, "", "0x2", null, null, 8, 0),
            new("s:1", "static", "parse", 85, "", "0x3", "parse", null),
        };

        var sorted = StalkIntelligenceBuilder.SortFactoryMap(targets);

        Assert.Equal("door-high", sorted[0].Label);
        Assert.Equal("door-low", sorted[1].Label);
    }

    [Fact]
    public void SortFactoryMap_FallsBackToScoreWithoutApproachCrossed()
    {
        var targets = new List<StalkIntelligenceTargetDto>
        {
            new("f:low", "frontier", "door-low", 40, "", "0x1", null, null),
            new("f:high", "frontier", "door-high", 90, "", "0x2", null, null),
        };

        var sorted = StalkIntelligenceBuilder.SortFactoryMap(targets);

        Assert.Equal("door-high", sorted[0].Label);
    }

    private static void WriteRichFrontier(string root, string project, int count, int topScore)
    {
        var dir = Path.Combine(root, "data", "stalk", project);
        Directory.CreateDirectory(dir);
        var frontiers = Enumerable.Range(0, count)
            .Select(i => new FrontierBranchDto(
                $"bb:0x401{i * 10:D3}->0x401{i * 10 + 20:D3}",
                "cfg-branch",
                topScore - i * 2,
                2,
                0.4,
                2,
                0.6,
                "parse_input",
                $"0x401{i * 10:D3}",
                $"0x401{i * 10 + 20:D3}",
                "demo.exe",
                "uncovered successor"))
            .ToList();
        var report = new FrontierReportDto(
            project,
            DateTime.UtcNow.ToString("O"),
            "cfg",
            "rich frontier",
            count * 2,
            count,
            null,
            frontiers,
            "hint");
        File.WriteAllText(
            Path.Combine(dir, FrontierEngine.FileName),
            JsonSerializer.Serialize(report, JsonOptions));
    }

    private static void WriteFrontier(string root, string project, int score)
    {
        var dir = Path.Combine(root, "data", "stalk", project);
        Directory.CreateDirectory(dir);
        var report = new FrontierReportDto(
            project,
            DateTime.UtcNow.ToString("O"),
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
            JsonSerializer.Serialize(report, JsonOptions));
    }

    private static void WriteStaticMap(string root, string project, int fuzzPriority)
    {
        var dir = Path.Combine(root, "data", "stalk", project);
        Directory.CreateDirectory(dir);
        var doc = new RandallAnalysisDocument(
            "2",
            "demo.exe",
            null,
            "0x400000",
            DateTime.UtcNow.ToString("O"),
            "test",
            [
                new RandallAnalysisFunctionDto(
                    "parse_input",
                    "0x401000",
                    96,
                    6,
                    40,
                    2,
                    4,
                    true,
                    true,
                    ["memcpy", "recv"],
                    fuzzPriority,
                    new RandallAnalysisFunctionCfgDto([
                        new RandallAnalysisBasicBlockDto("0x401000", 16, ["0x401010"], []),
                        new RandallAnalysisBasicBlockDto("0x401010", 16, [], ["0x401000"]),
                    ]),
                    UncoveredBlockCount: 3,
                    CoverageFraction: 0.25),
            ],
            [],
            [],
            [],
            []);
        File.WriteAllText(
            Path.Combine(dir, GhidraAnalysisBridge.FileName),
            JsonSerializer.Serialize(doc, JsonOptions));
    }

    private static string NewTempRoot()
    {
        var path = Path.Combine(Path.GetTempPath(), "randall-brain-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (Directory.Exists(path))
                Directory.Delete(path, recursive: true);
        }
        catch
        {
            /* ignore */
        }
    }
}
