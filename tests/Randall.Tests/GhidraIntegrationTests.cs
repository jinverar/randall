using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class GhidraIntegrationTests
{
    [Fact]
    public void ScriptBuilder_PaintsFullBbAndOptionalGoto()
    {
        var script = GhidraScriptBuilder.BuildColorScript(
            "test",
            [
                new("baseline", [new(0x1000, 16), new(0x1100, 8)], 255, 255, 0),
                new("novel", [new(0x2000, 32)], 255, 0, 0),
            ],
            goToRva: 0x2000,
            notes: "unit");

        Assert.Contains("base.add(rva)", script);
        Assert.Contains("start.add(size - 1)", script);
        Assert.Contains("getBackgroundColor", script);
        Assert.Contains("goTo(focus)", script);
        Assert.Contains("8192", script); // 0x2000 as decimal in base.add(...)
    }

    [Fact]
    public void FindNovelFocus_PicksFirstCrashOnlyEdge()
    {
        var baseline = new[] { "0:0x1000:16", "0:0x1100:16" };
        var crash = new[] { "0:0x1000:16", "0:0x2200:8", "0:0x1100:16" };
        var (edge, rva, index) = CrashStalker.FindNovelFocus(crash, baseline);
        Assert.Equal("0:0x2200:8", edge);
        Assert.Equal(0x2200, rva);
        Assert.Equal(1, index);
    }

    [Fact]
    public void GhidraExporter_WritesRealImportScript()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-ghidra-exp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var bundle = new TriageBundleDto(
                Guid.NewGuid(), "demo", Path.Combine(dir, "in.bin"), null, null, null, dir);
            File.WriteAllBytes(bundle.InputPath, [1, 2, 3]);
            GhidraExporter.WriteArtifacts(
                dir,
                bundle,
                edges: ["0:0x1000:16", "0:0x3000:8"],
                baselineEdges: ["0:0x1000:16"],
                goToRva: 0x3000,
                divergeEdge: "0:0x3000:8");

            var py = File.ReadAllText(Path.Combine(dir, "ghidra_import.py"));
            Assert.Contains("ColorizingService", py);
            Assert.DoesNotContain("script stub", py, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("crash-novel", py);
            Assert.Contains("goTo", py);
            Assert.True(File.Exists(Path.Combine(dir, "coverage_edges.txt")));
            Assert.True(File.Exists(Path.Combine(dir, "GHIDRA_README.txt")));
            var readme = File.ReadAllText(Path.Combine(dir, "DRAGON_DANCE.txt"));
            Assert.Contains("WITHOUT -dump_text", readme);
            Assert.Contains("PRIMARY", readme, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }
}
