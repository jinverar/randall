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
                new("baseline", [new(0x1000, 16, "0"), new(0x1100, 8, "0")], 255, 255, 0),
                new("novel", [new(0x2000, 32, "0")], 255, 0, 0),
            ],
            goToRva: 0x2000,
            notes: "unit",
            modules:
            [
                new("0", @"C:\DEV\savant.exe", 0x400000, 0x450000),
                new("1", @"C:\Windows\System32\ntdll.dll", 0x77000000, 0x77100000),
            ],
            bookmarkRvas: [0x2000, 0x1000]);

        Assert.Contains("base.add(rva)", script);
        Assert.Contains("start.add(size - 1)", script);
        Assert.Contains("getBackgroundColor", script);
        Assert.Contains("goTo(focus)", script);
        Assert.Contains("8192", script); // 0x2000 as decimal in base.add(...)
        Assert.Contains("allow_ids", script);
        Assert.Contains("setBookmark", script);
        Assert.Contains("4194304", script); // 0x400000 preferred base
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
            Assert.Contains("setBookmark", py);
            Assert.True(File.Exists(Path.Combine(dir, "coverage_edges.txt")));
            Assert.True(File.Exists(Path.Combine(dir, "GHIDRA_README.txt")));
            var readme = File.ReadAllText(Path.Combine(dir, "DRAGON_DANCE.txt"));
            Assert.Contains("WITHOUT -dump_text", readme);
            Assert.Contains("PRIMARY", readme, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("captureBinaryDrcov", readme);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void BuildDrcovArgs_TextVsBinary()
    {
        var text = DynamoRioRunner.BuildDrcovArgs("/tmp/t", "/bin/app", "{file}", dumpText: true);
        Assert.Contains("-dump_text", text);
        Assert.Contains("-logdir", text);

        var binary = DynamoRioRunner.BuildDrcovArgs("/tmp/b", "/bin/app", "", dumpText: false);
        Assert.DoesNotContain("-dump_text", binary);
        Assert.Contains("-t drcov", binary);
        Assert.Contains("-logdir", binary);
    }

    [Fact]
    public void WriteModulesSidecar_IncludesStartEnd()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-mod-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            GhidraScriptBuilder.WriteModulesSidecar(dir,
            [
                new("0", @"C:\DEV\app.exe", 0x400000, 0x450000),
            ]);
            var text = File.ReadAllText(Path.Combine(dir, "modules.txt"));
            Assert.Contains("0x400000", text);
            Assert.Contains("0x450000", text);
            Assert.Contains("app.exe", text);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }
}
