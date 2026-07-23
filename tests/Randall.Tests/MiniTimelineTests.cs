using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class MiniTimelineTests
{
    [Fact]
    public void Probe_DoesNotThrow_WhenToolsMissing()
    {
        var status = ZimmermanToolPaths.Probe(Path.GetTempPath());
        Assert.NotNull(status);
        // Temp path almost never has EZ tools
        Assert.False(status.HasCore);
        Assert.Empty(status.FoundLines());
    }

    [Fact]
    public void TryCapture_SoftFails_WithoutTools_AndWritesSummary()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-tl-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(dir);
            var id = Guid.NewGuid();
            var summary = MiniTimelineCapture.TryCapture(
                dir,
                id,
                DateTimeOffset.UtcNow,
                windowSeconds: 30,
                targetExe: "randall-vulnserver.exe",
                repoRoot: dir,
                projectName: "probe");
            Assert.False(summary.Ok);
            Assert.True(
                (summary.Error ?? summary.SummaryLine).Contains("not found", StringComparison.OrdinalIgnoreCase) ||
                (summary.Error ?? summary.SummaryLine).Contains("Windows-only", StringComparison.OrdinalIgnoreCase));
            Assert.True(File.Exists(MiniTimelineCapture.SummaryPath(dir, id)));
            var read = MiniTimelineCapture.TryRead(dir, id);
            Assert.NotNull(read);
            Assert.Equal(id, read!.CrashId);
            Assert.Equal(30, read.WindowSeconds);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* */ }
        }
    }

    [Fact]
    public void WindowSeconds_Clamped()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-tl-" + Guid.NewGuid().ToString("N"));
        try
        {
            var id = Guid.NewGuid();
            var summary = MiniTimelineCapture.TryCapture(dir, id, DateTimeOffset.UtcNow, windowSeconds: 1, repoRoot: dir);
            Assert.Equal(5, summary.WindowSeconds);
            summary = MiniTimelineCapture.TryCapture(dir, id, DateTimeOffset.UtcNow, windowSeconds: 99999, repoRoot: dir);
            Assert.Equal(3600, summary.WindowSeconds);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* */ }
        }
    }

    [Fact]
    public void FuzzConfig_MiniTimeline_DefaultsOff()
    {
        var fuzz = new FuzzConfig();
        Assert.False(fuzz.MiniTimeline);
        Assert.Equal(60, fuzz.MiniTimelineWindowSeconds);
    }

    [Fact]
    public void DocsCatalog_IncludesMiniTimeline()
    {
        Assert.Contains(DocsCatalog.Index, i => i.Path == "MINI_TIMELINE.md");
    }

    [Fact]
    public void FindPmlForRun_FindsDirectAndNewest()
    {
        var root = Path.Combine(Path.GetTempPath(), "randall-pml-" + Guid.NewGuid().ToString("N"));
        try
        {
            var runId = "demo_20260101";
            var runDir = Path.Combine(root, "data", "runs", runId);
            Directory.CreateDirectory(runDir);
            var pml = Path.Combine(runDir, "fuzz.pml");
            File.WriteAllText(pml, "fake");
            Assert.Equal(pml, ProcmonTimelineSlice.FindPmlForRun(root, runId));

            var older = Path.Combine(root, "data", "runs", "other_old");
            Directory.CreateDirectory(older);
            File.WriteAllText(Path.Combine(older, "fuzz.pml"), "x");
            File.SetLastWriteTimeUtc(Path.Combine(older, "fuzz.pml"), DateTime.UtcNow.AddHours(-2));

            var newer = Path.Combine(root, "data", "runs", "demo_new");
            Directory.CreateDirectory(newer);
            var newest = Path.Combine(newer, "fuzz.pml");
            File.WriteAllText(newest, "y");
            File.SetLastWriteTimeUtc(newest, DateTime.UtcNow);
            Assert.Equal(newest, ProcmonTimelineSlice.FindPmlForRun(root, null, "demo"));
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { /* */ }
        }
    }

    [Fact]
    public void GraphBuilder_WritesGraphAndMerged_FromCsvs()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-graph-" + Guid.NewGuid().ToString("N"));
        try
        {
            var id = Guid.NewGuid();
            var tl = MiniTimelineCapture.TimelineDir(dir, id);
            Directory.CreateDirectory(tl);
            File.WriteAllText(Path.Combine(tl, "evtx.csv"),
                "TimeCreated,EventId,Provider\n2026-01-01T12:00:00Z,1000,App\n");
            File.WriteAllText(Path.Combine(tl, "procmon.csv"),
                "Time of Day,Process Name,Operation,Path\n12:00:00.000,vuln.exe,ReadFile,C:\\x.bin\n");
            File.WriteAllText(Path.Combine(tl, "mft.csv"),
                "Created0x10,FileName,ParentPath\n2026-01-01T12:00:00Z,x.bin,C:\\\n");

            var summary = new MiniTimelineSummaryDto(
                Ok: true,
                Error: null,
                CrashId: id,
                Project: "demo",
                TargetExe: @"C:\lab\vuln.exe",
                AnchorUtc: DateTimeOffset.Parse("2026-01-01T12:00:00Z"),
                WindowStartUtc: DateTimeOffset.Parse("2026-01-01T11:59:00Z"),
                WindowEndUtc: DateTimeOffset.Parse("2026-01-01T12:01:00Z"),
                WindowSeconds: 60,
                ToolsUsed: ["EvtxECmd"],
                Artifacts: [],
                EvtxRows: 1,
                MftRows: 1,
                PrefetchRows: 0,
                AmcacheRows: 0,
                WerCopied: 0,
                Notes: [],
                SummaryLine: "test",
                CapturedAtUtc: DateTimeOffset.UtcNow,
                ProcmonRows: 1);

            var path = MiniTimelineGraphBuilder.Write(dir, id, summary, inputPath: @"C:\in\seed.bin");
            Assert.True(File.Exists(path));
            Assert.True(File.Exists(MiniTimelineGraphBuilder.MergedCsvPath(dir, id)));

            var graph = MiniTimelineGraphBuilder.TryRead(dir, id);
            Assert.NotNull(graph);
            Assert.Contains(graph!.Nodes, n => n.Kind == "crash");
            Assert.Contains(graph.Nodes, n => n.Kind == "input");
            Assert.Contains(graph.Nodes, n => n.Kind == "process");
            Assert.True(graph.Nodes.Count >= 4);
            Assert.True(graph.Edges.Count >= 3);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* */ }
        }
    }
}
