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
}
