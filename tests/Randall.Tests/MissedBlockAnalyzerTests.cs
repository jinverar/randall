using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class MissedBlockAnalyzerTests
{
    [Fact]
    public void Analyze_EmptyProject_ReturnsEmptyMode()
    {
        var root = NewTempRoot();
        try
        {
            var report = MissedBlockAnalyzer.Analyze("empty-proj", root, limit: 20);
            Assert.Equal("empty", report.Mode);
            Assert.Equal(0, report.MissedCount);
            Assert.Contains("baseline", report.WorkflowHint, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void Analyze_BaselineOnly_ReportsGapAndIdeas()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "miss-demo";
            StalkCampaignStore.AddLayer(new StalkLayerCreateRequest(
                project, "baseline", "happy path", null, null, null, null, "test"), root);
            // Rewrite edges for baseline + fuzzed with controlled sets
            var layers = StalkCampaignStore.ListLayers(project, root);
            Assert.Single(layers);
            WriteEdges(project, layers[0].Id, root, ["0:0x1000:16", "0:0x1100:16", "0:0x1200:16"]);

            var fuzzed = StalkCampaignStore.AddLayer(new StalkLayerCreateRequest(
                project, "fuzzed", "basic fuzz", null, null, null, null, "test"), root);
            WriteEdges(project, fuzzed.Id, root, ["0:0x1000:16"]); // abandoned 0x1100 / 0x1200

            var report = MissedBlockAnalyzer.Analyze(project, root, limit: 40);
            Assert.Equal("relative", report.Mode);
            Assert.Contains(report.Blocks, b => b.Category == "baseline-only");
            Assert.True(report.TopIdeas.Count > 0);
            Assert.Contains(report.TopIdeas, i => i.Priority is "high" or "medium");
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void Inventory_ImportThenNeverHit()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "inv-demo";
            var src = Path.Combine(root, "all-blocks.txt");
            File.WriteAllLines(src,
            [
                "0:0x2000:16",
                "0:0x2100:16",
                "0:0x2200:16",
            ]);

            var imported = MissedBlockAnalyzer.ImportInventory(project, src, root);
            Assert.Equal(3, imported.BlockCount);
            Assert.True(File.Exists(imported.InventoryPath));

            var layer = StalkCampaignStore.AddLayer(new StalkLayerCreateRequest(
                project, "fuzzed", "partial", null, null, null, null, null), root);
            WriteEdges(project, layer.Id, root, ["0:0x2000:16"]);

            var report = MissedBlockAnalyzer.Analyze(project, root, limit: 20);
            Assert.Equal("inventory", report.Mode);
            Assert.Equal(2, report.MissedCount);
            Assert.All(report.Blocks, b => Assert.Equal("never-hit", b.Category));
            Assert.Contains(report.Blocks, b => b.Address.Contains("2100", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void FrontierGap_EmitsHoleBetweenHits()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "gap-demo";
            var layer = StalkCampaignStore.AddLayer(new StalkLayerCreateRequest(
                project, "fuzzed", "hits", null, null, null, null, null), root);
            // Large hole between 0x1000 and 0x1400 (>= 0x80)
            WriteEdges(project, layer.Id, root, ["1:0x1000:16", "1:0x1400:16"]);

            var report = MissedBlockAnalyzer.Analyze(project, root, limit: 20);
            Assert.Contains(report.Blocks, b => b.Category == "frontier-gap");
        }
        finally
        {
            TryDelete(root);
        }
    }

    private static void WriteEdges(string project, string layerId, string root, IEnumerable<string> edges)
    {
        var path = Path.Combine(StalkCampaignStore.ProjectDir(project, root), $"layer-{layerId}.edges.txt");
        File.WriteAllLines(path, edges);
        // Keep meta blockCount roughly in sync (optional for analyzer)
        var metaPath = Path.Combine(StalkCampaignStore.ProjectDir(project, root), $"layer-{layerId}.json");
        if (File.Exists(metaPath))
        {
            var layer = System.Text.Json.JsonSerializer.Deserialize<StalkLayerDto>(File.ReadAllText(metaPath));
            if (layer is not null)
            {
                var updated = layer with { BlockCount = edges.Count() };
                File.WriteAllText(metaPath, System.Text.Json.JsonSerializer.Serialize(updated, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
            }
        }
    }

    private static string NewTempRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "randall-missed-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static void TryDelete(string root)
    {
        try { Directory.Delete(root, recursive: true); }
        catch { /* best effort */ }
    }
}
