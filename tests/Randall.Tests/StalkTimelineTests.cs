using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class StalkTimelineTests
{
    private static CrashSummaryDto Crash(int iteration, Guid? id = null, string? runId = "run-a") =>
        new(
            id ?? Guid.NewGuid(),
            "vulnserver",
            iteration,
            "bitflip",
            "hash",
            "input.bin",
            null,
            null,
            null,
            null,
            runId,
            DateTimeOffset.UtcNow);

    [Fact]
    public void Live_overlay_without_journal_places_crash_markers_not_flat_hits()
    {
        // Repro: OverlayLiveRunCounters fabricates RunId="live" with high Iterations;
        // crashes outside the last-200 window must still paint as red tip bars (CrashId retained).
        var crashA = Crash(42);
        var crashB = Crash(180);
        var run = new FuzzRunManifestDto(
            "live",
            "vulnserver",
            "live",
            "projects/vulnserver.yaml",
            DateTimeOffset.UtcNow,
            null,
            false,
            true,
            "novelty",
            "live overlay",
            Iterations: 500,
            CrashesFound: 2);

        var timeline = StalkDashboard.BuildTimelineSnapshot(run, latestDetail: null, [crashA, crashB]);

        Assert.NotEmpty(timeline);
        Assert.True(timeline.Count <= 200);
        var crashes = timeline.Where(p => p.Kind == "crash" && p.Crashed).ToList();
        Assert.True(crashes.Count >= 2, $"Expected ≥2 crash bars, got {crashes.Count}");
        Assert.Contains(crashes, p => p.CrashId == crashA.Id);
        Assert.Contains(crashes, p => p.CrashId == crashB.Id);
        // Pinned into the visible window so sort-by-iteration clients cannot drop them.
        Assert.All(crashes, p => Assert.True(p.Iteration >= 301, $"crash bar iter {p.Iteration} outside window"));
        Assert.Contains(timeline, p => p.Kind is "hit" or "novel");
    }

    [Fact]
    public void Live_for_project_ignores_runid_mismatch_and_shows_catalog_crashes()
    {
        // Live fuzz overlays an older journal RunId while catalog crashes carry the new RunId.
        var crash = Crash(12, runId: "brand-new-run");
        var run = new FuzzRunManifestDto(
            "stale-old-run",
            "vulnserver",
            "tcp",
            "projects/vulnserver.yaml",
            DateTimeOffset.UtcNow,
            null,
            false,
            false,
            "novelty",
            "stale journal",
            Iterations: 80,
            CrashesFound: 1);

        var timeline = StalkDashboard.BuildTimelineSnapshot(
            run, latestDetail: null, [crash], liveForProject: true);

        var bar = Assert.Single(timeline, p => p.Kind == "crash" && p.Crashed);
        Assert.Equal(crash.Id, bar.CrashId);
    }

    [Fact]
    public void Synthetic_window_marks_tip_crash_when_catalog_empty_but_counter_positive()
    {
        var run = new FuzzRunManifestDto(
            "live",
            "demo",
            "live",
            "projects/demo.yaml",
            DateTimeOffset.UtcNow,
            null,
            false,
            false,
            "novelty",
            "live",
            Iterations: 120,
            CrashesFound: 1);

        var timeline = StalkDashboard.BuildTimelineSnapshot(run, latestDetail: null, []);

        Assert.Contains(timeline, p => p.Kind == "crash" && p.Crashed);
        Assert.Equal("crash", timeline[^1].Kind);
    }

    [Fact]
    public void Journal_missing_Crashed_flag_still_upgraded_from_crash_catalog()
    {
        var crashId = Guid.NewGuid();
        var crash = Crash(7, crashId, runId: "proj_run1");
        var run = new FuzzRunManifestDto(
            "proj_run1",
            "proj",
            "tcp",
            "projects/proj.yaml",
            DateTimeOffset.UtcNow,
            null,
            false,
            false,
            "novelty",
            "note",
            Iterations: 20,
            CrashesFound: 1);

        // No iterations.jsonl on disk for this fabricated runId → synthetic path + EnsureCrashMarkers.
        var timeline = StalkDashboard.BuildTimelineSnapshot(run, latestDetail: null, [crash]);

        var bar = Assert.Single(timeline, p => p.Iteration == 7 && p.Kind == "crash");
        Assert.True(bar.Crashed);
        Assert.Equal(crashId, bar.CrashId);
    }
}
