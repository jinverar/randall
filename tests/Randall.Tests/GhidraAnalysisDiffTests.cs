using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class GhidraAnalysisDiffTests
{
    [Fact]
    public void ComputeChangedFunctions_DetectsModifiedAndAdded()
    {
        var baseline = Doc(
            "0x400000",
            Fn("handle", "0x401000", 100, 10, 20),
            Fn("old_only", "0x402000", 50, 5, 8));

        var current = Doc(
            "0x400000",
            Fn("handle", "0x401000", 180, 14, 35),
            Fn("new_fn", "0x403000", 64, 6, 12));

        var changed = GhidraAnalysisDiff.ComputeChangedFunctions(current, baseline);

        Assert.Contains(changed, c => c.ChangeKind == "modified" && c.Name == "handle");
        Assert.Contains(changed, c => c.ChangeKind == "added" && c.Name == "new_fn");
        Assert.Contains(changed, c => c.ChangeKind == "removed" && c.Name == "old_only");
    }

    [Fact]
    public void MergeDiff_WritesDiffMeta()
    {
        var baseline = Doc("0x400000", Fn("a", "0x401000", 10, 2, 4));
        var current = Doc("0x400000", Fn("a", "0x401000", 40, 8, 16));

        var merged = GhidraAnalysisDiff.MergeDiff(current, baseline, @"C:\baseline.json");

        Assert.NotNull(merged.DiffMeta);
        Assert.Equal(@"C:\baseline.json", merged.DiffMeta!.BaselinePath);
        Assert.Equal(GhidraAnalysisDiff.JsonMergeSource, merged.DiffMeta.Source);
        Assert.NotNull(merged.ChangedFunctions);
        Assert.Single(merged.ChangedFunctions!);
    }

    [Fact]
    public void ParseBsimJson_ReadsSimilarityRows()
    {
        var root = CrashCatalog.FindRepoRoot();
        if (root is null)
            return;

        var path = Path.Combine(Path.GetTempPath(), "bsim-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            File.WriteAllText(path, """
                [
                  {
                    "queryFunction": "parse",
                    "queryAddress": "0x1000",
                    "matchFunction": "parse_v2",
                    "matchAddress": "0x2000",
                    "similarity": 0.88
                  }
                ]
                """);

            var rows = GhidraAnalysisDiff.ParseBsimJson(path);
            Assert.Single(rows);
            Assert.Equal("parse", rows[0].QueryFunction);
            Assert.Equal(0.88, rows[0].Similarity);
        }
        finally
        {
            if (File.Exists(path))
                File.Delete(path);
        }
    }

    private static RandallAnalysisDocument Doc(string imageBase, params RandallAnalysisFunctionDto[] functions) =>
        new(
            "1",
            "demo.exe",
            null,
            imageBase,
            "2026-01-01T00:00:00Z",
            "test",
            functions,
            [],
            [],
            [],
            []);

    private static RandallAnalysisFunctionDto Fn(
        string name, string address, int size, int bb, int complexity) =>
        new(name, address, size, bb, complexity, 0, 0, false, false, [], 0);
}
