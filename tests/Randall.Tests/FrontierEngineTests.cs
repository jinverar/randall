using System.Text.Json;
using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class FrontierEngineTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    [Fact]
    public void ComputeFrontierScore_RisesWithFactors()
    {
        var low = FrontierEngine.ComputeFrontierScore(1, 0.2, 1, 0.3);
        var high = FrontierEngine.ComputeFrontierScore(5, 0.9, 4, 0.95);
        Assert.True(high > low);
        Assert.InRange(high, 1, 100);
        Assert.InRange(low, 1, 100);
    }

    [Fact]
    public void Score_CfgBranch_PersistsFrontierJson()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "frontier-cfg";
            var dir = Path.Combine(root, "data", "stalk", project);
            Directory.CreateDirectory(dir);

            File.WriteAllLines(Path.Combine(dir, "coverage_edges.txt"), ["0:0x1000:16"]);

            var doc = new RandallAnalysisDocument(
                "2", "demo.exe", null, "0x400000", "2026-01-01T00:00:00Z", "test",
                [
                    new RandallAnalysisFunctionDto(
                        "parse", "0x401000", 64, 4, 30, 1, 2, true, true,
                        ["memcpy"], 50,
                        new RandallAnalysisFunctionCfgDto([
                            new RandallAnalysisBasicBlockDto("0x401000", 16, ["0x401010"], []),
                            new RandallAnalysisBasicBlockDto("0x401010", 16, ["0x401020"], ["0x401000"]),
                            new RandallAnalysisBasicBlockDto("0x401020", 16, ["0x401030"], ["0x401010"]),
                            new RandallAnalysisBasicBlockDto("0x401030", 16, [], ["0x401020"]),
                        ])),
                ],
                [], [], [], []);

            File.WriteAllText(
                Path.Combine(dir, GhidraAnalysisBridge.FileName),
                JsonSerializer.Serialize(doc, JsonOptions));

            var report = FrontierEngine.Score(project, root, limit: 10);
            Assert.Equal("cfg", report.Mode);
            Assert.True(report.Frontiers.Count > 0);
            Assert.Contains(report.Frontiers, f => f.Kind == "cfg-branch");
            Assert.True(report.Frontiers[0].Score >= report.Frontiers[^1].Score);

            var path = FrontierEngine.FrontierPath(project, root);
            Assert.True(File.Exists(path));
            var loaded = FrontierEngine.TryLoad(project, root);
            Assert.NotNull(loaded);
            Assert.Equal(report.FrontierCount, loaded!.FrontierCount);
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void Score_NoAnalysis_UsesEdgeGapsWhenCoverageExists()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "frontier-gap";
            StalkCampaignStore.AddLayer(new StalkLayerCreateRequest(
                project, "baseline", "happy", null, null, null, null, "test"), root);
            var layers = StalkCampaignStore.ListLayers(project, root);
            WriteEdges(project, layers[0].Id, root,
                ["0:0x1000:16", "0:0x1100:16", "0:0x1200:16"]);

            var fuzzed = StalkCampaignStore.AddLayer(new StalkLayerCreateRequest(
                project, "fuzzed", "basic", null, null, null, null, "test"), root);
            WriteEdges(project, fuzzed.Id, root, ["0:0x1000:16"]);

            var report = FrontierEngine.Score(project, root, limit: 20, persist: false);
            Assert.NotEqual("empty", report.Mode);
            Assert.True(report.Frontiers.Count > 0);
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void Score_EmptyProject_ReturnsEmptyMode()
    {
        var root = NewTempRoot();
        try
        {
            var report = FrontierEngine.Score("empty-frontier", root, persist: false);
            Assert.Equal("empty", report.Mode);
            Assert.Empty(report.Frontiers);
        }
        finally
        {
            TryDelete(root);
        }
    }

    private static string NewTempRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "randall-frontier-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static void WriteEdges(string project, string layerId, string root, IEnumerable<string> edges)
    {
        var path = Path.Combine(root, "data", "stalk", project, $"layer-{layerId}.edges.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllLines(path, edges);
    }

    private static void TryDelete(string root)
    {
        try { Directory.Delete(root, true); } catch { /* ignore */ }
    }
}
