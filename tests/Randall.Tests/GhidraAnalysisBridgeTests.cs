using System.Text.Json;
using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class GhidraAnalysisBridgeTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    [Fact]
    public void ComputeFuzzPriority_WeightsSinksAndComplexity()
    {
        var low = GhidraAnalysisBridge.ComputeFuzzPriority(10, 4, [], false, 0);
        var high = GhidraAnalysisBridge.ComputeFuzzPriority(80, 40, ["memcpy", "strcpy"], true, 3);
        Assert.True(high > low);
        Assert.InRange(high, 1, 100);
    }

    [Fact]
    public void ComputeCoverageAwareFuzzPriority_RisesWithGaps()
    {
        var covered = GhidraCoverageOverlay.ComputeCoverageAwareFuzzPriority(40, 90, 50, 0, 1.0);
        var gapped = GhidraCoverageOverlay.ComputeCoverageAwareFuzzPriority(40, 90, 50, 5, 0.25);
        Assert.True(gapped >= covered);
        Assert.InRange(gapped, 1, 100);
    }

    [Fact]
    public void IsBlockCovered_MatchesRvaOverlap()
    {
        var bb = new RandallAnalysisBasicBlockDto("0x401000", 16, [], []);
        var coverage = new List<GhidraCoverageOverlay.CoverageBlock> { new(0x1000, 32) };
        Assert.True(GhidraCoverageOverlay.IsBlockCovered(bb, coverage, 0x400000));
    }

    [Fact]
    public void Apply_OverlayMarksFunctionsAndSummary()
    {
        var root = CrashCatalog.FindRepoRoot();
        if (root is null)
            return;

        var project = "ghidra-overlay-" + Guid.NewGuid().ToString("N")[..8];
        var dir = Path.Combine(root, "data", "stalk", project);
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllLines(Path.Combine(dir, "coverage_edges.txt"), ["0:0x1000:16"]);

            var doc = new RandallAnalysisDocument(
                "2", "demo.exe", null, "0x400000", "2026-01-01T00:00:00Z", "test",
                [
                    new RandallAnalysisFunctionDto(
                        "parse", "0x401000", 64, 3, 20, 1, 2, true, true,
                        ["memcpy"], 50,
                        new RandallAnalysisFunctionCfgDto([
                            new RandallAnalysisBasicBlockDto("0x401000", 16, ["0x401010"], []),
                            new RandallAnalysisBasicBlockDto("0x401010", 16, [], ["0x401000"]),
                        ])),
                ],
                [], [], [], []);

            var enriched = GhidraCoverageOverlay.Apply(doc, project, root);
            Assert.NotNull(enriched.CoverageSummary);
            Assert.Equal(1, enriched.Functions[0].CoveredBlockCount);
            Assert.Equal(1, enriched.Functions[0].UncoveredBlockCount);
            Assert.True(enriched.Functions[0].FuzzPriority >= 50);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void OracleHints_SummarizeTopFunctionsAndGaps()
    {
        var root = CrashCatalog.FindRepoRoot();
        if (root is null)
            return;

        var project = "ghidra-hints-" + Guid.NewGuid().ToString("N")[..8];
        var dir = Path.Combine(root, "data", "stalk", project);
        Directory.CreateDirectory(dir);
        try
        {
            var doc = new RandallAnalysisDocument(
                "2", "x.exe", null, "0x400000", "2026-01-01T00:00:00Z", "test",
                [
                    new RandallAnalysisFunctionDto("low", "0x1000", 10, 2, 4, 0, 1, false, false, [], 20),
                    new RandallAnalysisFunctionDto(
                        "hot", "0x2000", 200, 30, 50, 2, 5, true, true, ["strcpy"], 92,
                        null, 5, 25, 0.17, 3, false),
                ],
                [], [], [], [],
                CoverageSummary: new RandallAnalysisCoverageSummaryDto(
                    30, 5, 25, 0.17, 0, 1, ["hot"]));
            File.WriteAllText(path: Path.Combine(dir, GhidraAnalysisBridge.FileName),
                contents: JsonSerializer.Serialize(doc, JsonOptions));

            var hints = GhidraAnalysisOracleHints.TryBuild(project, root);
            Assert.NotNull(hints);
            Assert.Equal("hot", hints!.TopFunctions[0].Name);
            Assert.Contains("92/100", hints.Summary);
            Assert.Contains("5/30 BBs", hints.CoverageGapSummary);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void StaticMapBias_ReturnsBoostWhenGapsExist()
    {
        var root = CrashCatalog.FindRepoRoot();
        if (root is null)
            return;

        var project = "ghidra-bias-" + Guid.NewGuid().ToString("N")[..8];
        var dir = Path.Combine(root, "data", "stalk", project);
        Directory.CreateDirectory(dir);
        try
        {
            var doc = new RandallAnalysisDocument(
                "2", "x.exe", null, "0x400000", "2026-01-01T00:00:00Z", "test",
                [
                    new RandallAnalysisFunctionDto(
                        "hot", "0x2000", 200, 30, 50, 2, 5, true, true, ["strcpy"], 92,
                        null, 5, 25, 0.17, 3, false),
                ],
                [], [], [], [],
                CoverageSummary: new RandallAnalysisCoverageSummaryDto(
                    30, 5, 25, 0.17, 0, 1, ["hot"]));
            File.WriteAllText(
                Path.Combine(dir, GhidraAnalysisBridge.FileName),
                JsonSerializer.Serialize(doc, JsonOptions));

            var boost = GhidraStaticMapBias.NovelCoverageEnergyBoost(project, 3, enabled: true, root);
            Assert.InRange(boost, 1, 8);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }
}
