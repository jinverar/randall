using System.Text.Json;
using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Infrastructure.Mutators;
using Xunit;

namespace Randall.Tests;

public class TargetGravityEngineTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    [Fact]
    public void ComputeGravityScore_RisesWithRiskAndFallsWithDistance()
    {
        var near = TargetGravityEngine.ComputeGravityScore(90, 0.9, 1);
        var far = TargetGravityEngine.ComputeGravityScore(90, 0.9, 8);
        var lowRisk = TargetGravityEngine.ComputeGravityScore(20, 0.9, 1);

        Assert.True(near > far);
        Assert.True(near > lowRisk);
        Assert.InRange(near, 1, 100);
    }

    [Fact]
    public void Score_CfgWithDangerousCall_PersistsGravityJson()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "gravity-cfg";
            var dir = Path.Combine(root, "data", "stalk", project);
            Directory.CreateDirectory(dir);

            File.WriteAllLines(Path.Combine(dir, "coverage_edges.txt"), ["0:0x1000:16"]);

            var doc = new RandallAnalysisDocument(
                "2", "demo.exe", null, "0x400000", "2026-01-01T00:00:00Z", "test",
                [
                    new RandallAnalysisFunctionDto(
                        "parse", "0x401000", 64, 4, 30, 1, 2, true, true,
                        ["strcpy"], 50,
                        new RandallAnalysisFunctionCfgDto([
                            new RandallAnalysisBasicBlockDto("0x401000", 16, ["0x401010"], []),
                            new RandallAnalysisBasicBlockDto("0x401010", 16, ["0x401020"], ["0x401000"]),
                            new RandallAnalysisBasicBlockDto("0x401020", 16, [], ["0x401010"]),
                        ])),
                ],
                [], [],
                [new RandallAnalysisSinkDto("strcpy", "0x402000", "sink", 85, ["parse"])],
                [], []);

            File.WriteAllText(
                Path.Combine(dir, GhidraAnalysisBridge.FileName),
                JsonSerializer.Serialize(doc, JsonOptions));

            var report = TargetGravityEngine.Score(project, root, limit: 10);
            Assert.Equal("cfg", report.Mode);
            Assert.True(report.Wells.Count > 0);
            Assert.Contains(report.Wells, w => w.Kind is "ghidra-dangerous" or "sink-call");
            Assert.True(report.Wells[0].GravityScore >= report.Wells[^1].GravityScore);

            var path = TargetGravityEngine.GravityPath(project, root);
            Assert.True(File.Exists(path));
            var loaded = TargetGravityEngine.TryLoad(project, root);
            Assert.NotNull(loaded);
            Assert.Equal(report.WellCount, loaded!.WellCount);
            Assert.True(loaded.TopSnapshots.Count > 0);
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void Score_StaleWells_DecayOnRefresh()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "gravity-decay";
            TargetGravityEngine.Save(new TargetGravityReportDto(
                project,
                DateTime.UtcNow.AddHours(-2).ToString("O"),
                "surface",
                "prior",
                1,
                1,
                60,
                [new TargetGravityWellDto("stale:1", "missed-surface", 60, 50, 0.8, 3, "mod", "0x3000", null, "old well")],
                "hint",
                [new TargetGravityTopSnapshotDto("stale:1", 60, "0x3000", "old well")]), root);

            var stalkDir = Path.Combine(root, "data", "stalk", project);
            Directory.CreateDirectory(stalkDir);
            File.WriteAllLines(Path.Combine(stalkDir, "inventory.blocks.txt"), ["0:0x00001080:16"]);
            var corpus = Path.Combine(root, "data", "corpus", project);
            Directory.CreateDirectory(corpus);
            File.WriteAllLines(Path.Combine(corpus, "edges.txt"), ["0:0x00002000:16"]);

            var report = TargetGravityEngine.Score(project, root, limit: 10);
            Assert.Contains(report.Wells, w => w.Key == "stale:1" && w.GravityScore < 60);
            Assert.True(report.TopSnapshots.Count > 0);
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void Score_MissedSurfaceWithoutCfg_ProducesSurfaceWells()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "gravity-surface";
            var stalkDir = Path.Combine(root, "data", "stalk", project);
            Directory.CreateDirectory(stalkDir);
            File.WriteAllLines(Path.Combine(stalkDir, "inventory.blocks.txt"), ["0:0x00001080:16"]);
            var corpus = Path.Combine(root, "data", "corpus", project);
            Directory.CreateDirectory(corpus);
            File.WriteAllLines(Path.Combine(corpus, "edges.txt"), ["0:0x00002000:16"]);

            var report = TargetGravityEngine.Score(project, root, persist: false);
            Assert.NotEqual("empty", report.Mode);
            Assert.Contains(report.Wells, w => w.Kind == "missed-surface");
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void TryGetTopPressure_ReturnsTopWell()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "gravity-top";
            TargetGravityEngine.Save(new TargetGravityReportDto(
                project,
                DateTime.UtcNow.ToString("O"),
                "surface",
                "test",
                2,
                2,
                72,
                [
                    new TargetGravityWellDto("a", "missed-surface", 72, 60, 0.9, 2, "mod", "0x1080", "memcpy", "test"),
                    new TargetGravityWellDto("b", "missed-surface", 40, 40, 0.7, 4, "mod", "0x2000", null, "test"),
                ],
                "hint",
                [
                    new TargetGravityTopSnapshotDto("a", 72, "memcpy", "test"),
                    new TargetGravityTopSnapshotDto("b", 40, "0x2000", "test"),
                ]), root);

            var top = TargetGravityEngine.TryGetTopPressure(project, root);
            Assert.NotNull(top);
            Assert.Equal(72, top!.Value.Score);
            Assert.Equal("memcpy", top.Value.Label);
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void HuntPolicy_ReadsGravityPressure_ForFrontierCandidate()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "gravity-hunt";
            var dir = Path.Combine(root, "data", "stalk", project);
            Directory.CreateDirectory(dir);

            var frontier = new FrontierReportDto(
                project, DateTime.UtcNow.ToString("O"), "cfg", "test", 4, 1, null,
                [
                    new FrontierBranchDto(
                        "bb:0x401000->0x401020", "cfg-branch", 70, 2, 0.5, 2, 0.7,
                        "parse", "0x401000", "0x401020", "demo.exe", "gray door"),
                ],
                "hint");
            File.WriteAllText(Path.Combine(dir, FrontierEngine.FileName),
                JsonSerializer.Serialize(frontier, JsonOptions));

            TargetGravityEngine.Save(new TargetGravityReportDto(
                project, DateTime.UtcNow.ToString("O"), "cfg", "test", 4, 1, 80,
                [new TargetGravityWellDto("g1", "sink-call", 80, 85, 0.9, 2, "parse", "0x401020", "strcpy", "pull")],
                "hint",
                [new TargetGravityTopSnapshotDto("g1", 80, "strcpy", "pull")]), root);

            var brain = new RandallBrain();
            var signals = brain.LoadSignals(project, root);
            var mutators = BuiltInMutators.Create(["havoc", "bitflip"], seed: 4);
            var policy = HuntPolicyEngine.Evaluate(new HuntPolicyEngine.Context(
                signals, [], null, mutators, 0.3, 5, 1.0, 0.0, project, root));

            Assert.Contains(policy.Terms, t => t.Label.Contains("gravity", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            TryDelete(root);
        }
    }

    private static string NewTempRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "randall-gravity-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static void TryDelete(string root)
    {
        try { Directory.Delete(root, true); } catch { /* ignore */ }
    }
}
