using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class CounterfactualEngineTests
{
    [Fact]
    public void BuildPlan_emits_sweep_and_boundary_probes()
    {
        var id = Guid.NewGuid();
        var payload = new byte[64];
        payload[40] = 0x41;

        var plan = CounterfactualEngine.BuildPlan(id, "lab", payload, suspectedOffset: 40);

        Assert.True(plan.Ok);
        Assert.Equal(40, plan.SuspectedOffset);
        Assert.Contains(plan.Probes, p => p.Kind == HypothesisExperimentKind.SweepOffset);
        Assert.Contains(plan.Probes, p => p.Kind == HypothesisExperimentKind.BoundaryProbe);
        Assert.All(plan.Probes, p => Assert.Equal(CounterfactualOutcome.Pending, p.Outcome));
    }

    [Fact]
    public void Evaluate_finds_smallest_safe_change_when_flip_clears_bug()
    {
        var id = Guid.NewGuid();
        var payload = new byte[32];
        payload[8] = 0xFF;

        // "Crash" only when byte 8 remains 0xFF (simulates length/marker field).
        bool StillCrashes(byte[] p) => p.Length > 8 && p[8] == 0xFF;

        var report = CounterfactualEngine.Evaluate(
            id, "lab", payload, StillCrashes, suspectedOffset: 8);

        Assert.True(report.Ok);
        Assert.NotNull(report.SmallestSafeChange);
        Assert.Equal(CounterfactualOutcome.SafeAdjacent, report.SmallestSafeChange!.Outcome);
        Assert.True(report.SafeAdjacentCount > 0);
        Assert.Contains("Smallest safe change", report.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("shellcode", report.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Evaluate_all_corrupt_reports_no_boundary()
    {
        var id = Guid.NewGuid();
        var payload = new byte[16];
        var report = CounterfactualEngine.Evaluate(id, "lab", payload, _ => true, suspectedOffset: 4);

        Assert.True(report.Ok);
        Assert.Null(report.SmallestSafeChange);
        Assert.Equal(0, report.SafeAdjacentCount);
        Assert.True(report.StillCorruptCount > 0);
    }

    [Fact]
    public void PersistForCrash_round_trips_plan()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randfuzz-cf-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            var payload = new byte[24];
            var written = CounterfactualEngine.PersistForCrash(dir, id, "lab", payload, suspectedOffset: 4);
            var loaded = CounterfactualEngine.TryReadForCrash(dir, id);

            Assert.True(File.Exists(CounterfactualEngine.PathFor(dir, id)));
            Assert.NotNull(loaded);
            Assert.Equal(written.Probes.Count, loaded!.Probes.Count);
            Assert.Equal(4, loaded.SuspectedOffset);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void ResolveOffset_prefers_corruption_pattern_depth()
    {
        var chain = new CrashCorruptionChainDto(
            true, Guid.NewGuid(), "lab", "MEDIUM", "x",
            "len", "expand", 12, null, ["expand"],
            [new CorruptionChainStepDto(1, "input", "len", "12")],
            null, null, DateTimeOffset.UtcNow);

        var offset = CounterfactualEngine.ResolveOffset(null, null, null, chain, 64);
        Assert.Equal(12, offset);
    }
}
