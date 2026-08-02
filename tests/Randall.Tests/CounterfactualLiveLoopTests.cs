using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class CounterfactualLiveLoopTests
{
    [Fact]
    public void Run_execute_observe_persist_updates_hypothesis_and_report()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randfuzz-cf-live-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            var payload = new byte[32];
            payload[8] = 0xFF;

            // Seed a TriggerSensitivity hypothesis — safe-adjacent must not leak onto other kinds.
            var hyp = new HypothesisDto(
                Guid.NewGuid().ToString("N"),
                id,
                "Byte at offset 8 gates the crash",
                60,
                new HypothesisExperimentDto(
                    HypothesisExperimentKind.SweepOffset,
                    "sweep around marker",
                    OffsetBytes: 8,
                    SweepRange: 4),
                "Flipping the marker clears the fault",
                HypothesisStatus.Proposed,
                TypeId: "h-cf-live",
                Kind: HypothesisKind.TriggerSensitivity,
                ExpectedPredicate: new ExpectedPredicate(HypothesisPredicateKind.TriggerSensitiveRegion));
            HypothesisEngine.Write(dir, new HypothesisSetDto(
                true, id, "lab", [hyp], DateTimeOffset.UtcNow,
                SchemaVersion: HypothesisEngine.CurrentSchemaVersion));

            // Influence map so RefreshFromHypotheses has a target.
            InfluenceEngine.Write(dir, new CrashInfluenceMapDto(
                true, id, "lab", "LOW", "seed",
                [new InfluenceLinkDto(
                    "link-8",
                    new InfluenceRegionDto(8, 9, 1, "marker", null, null),
                    new InfluencedStateDto(InfluencedStateKind.Length, "len"),
                    InfluenceConfirmationStatus.Candidate,
                    "marker length",
                    [])],
                [],
                DateTimeOffset.UtcNow));

            bool StillCrashes(byte[] p) => p.Length > 8 && p[8] == 0xFF;

            var result = CounterfactualLiveLoop.Run(
                dir, id, "lab", payload, StillCrashes,
                maxProbes: 5,
                settleSkeptic: false,
                suspectedOffset: 8);

            Assert.True(result.Ok);
            Assert.True(result.LiveExecuted);
            Assert.True(result.ExperimentsExecuted > 0);
            Assert.True(result.ExperimentsExecuted <= 5);
            Assert.True(result.Report.LiveExecuted);
            Assert.NotNull(result.Report.SmallestSafeChange);

            // Persist: counterfactual file exists with live flags.
            var loaded = CounterfactualEngine.TryReadForCrash(dir, id);
            Assert.NotNull(loaded);
            Assert.True(loaded!.LiveExecuted);
            Assert.Equal(result.ExperimentsExecuted, loaded.ExperimentsExecuted);
            Assert.Contains(loaded.Probes, p => p.Outcome == CounterfactualOutcome.SafeAdjacent);

            // TriggerSensitivity support updated; instance id (not type id) recorded.
            var hypLoaded = HypothesisEngine.TryReadForCrash(dir, id);
            Assert.NotNull(hypLoaded);
            var updated = hypLoaded!.Hypotheses.First(h => h.TypeId == "h-cf-live" || h.Id == hyp.Id);
            Assert.True(updated.SupportScore > 60);
            Assert.Equal(HypothesisKind.TriggerSensitivity, updated.Kind);
            Assert.NotNull(updated.Result);
            Assert.Contains("Counterfactual live", updated.Result!.Observation ?? "", StringComparison.OrdinalIgnoreCase);
            Assert.Contains(updated.Id, result.Report.UpdatedHypothesisIds ?? []);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Run_respects_max_probe_budget()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randfuzz-cf-budget-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            var payload = new byte[24];
            var calls = 0;
            bool StillCrashes(byte[] _)
            {
                calls++;
                return true;
            }

            var result = CounterfactualLiveLoop.Run(
                dir, id, "lab", payload, StillCrashes,
                maxProbes: 3,
                settleSkeptic: false,
                suspectedOffset: 4);

            Assert.True(result.LiveExecuted);
            Assert.Equal(3, result.ExperimentsExecuted);
            Assert.Equal(3, calls);
            Assert.Contains(result.Report.Probes, p => p.Outcome == CounterfactualOutcome.Pending);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Run_settles_skeptic_via_neutralize_hook()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randfuzz-cf-skep-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            var payload = new byte[32];
            payload[8] = 0xAA;

            var plan = ResearchPlannerEngine.PersistForCrash(dir, id, "lab",
                rootCause: new RootCauseAnalysisDto(
                    true, id, "lab",
                    new RootCauseCandidate(
                        RootCauseCategory.BoundsViolation,
                        "Parse", null, "memcpy", "len@8", null, null,
                        [], "HIGH", ["av"], ["bounds"], []),
                    "bounds at 8",
                    At: DateTimeOffset.UtcNow));
            SkepticEngine.PersistForCrash(dir, id, "lab", plan);

            // Crash only when byte 8 is 0xAA — neutralize/minimize at 8 clears it.
            bool StillCrashes(byte[] p) => p.Length > 8 && p[8] == 0xAA;

            var result = CounterfactualLiveLoop.Run(
                dir, id, "lab", payload, StillCrashes,
                maxProbes: 4,
                settleSkeptic: true,
                maxSkepticChallenges: 1,
                suspectedOffset: 8);

            Assert.NotNull(result.Skeptic);
            Assert.Contains(result.Skeptic!.Challenges,
                c => c.Status is SkepticChallengeStatus.Survived
                    or SkepticChallengeStatus.Falsified
                    or SkepticChallengeStatus.Inconclusive);
            var persisted = SkepticEngine.TryReadForCrash(dir, id);
            Assert.NotNull(persisted);
            Assert.Contains(persisted!.Challenges, c => c.Status != SkepticChallengeStatus.Proposed);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void PersistOrRunLive_reuses_prior_live_report_without_force()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randfuzz-cf-reuse-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            var payload = new byte[16];
            var calls = 0;
            bool StillCrashes(byte[] _)
            {
                calls++;
                return false;
            }

            var first = CounterfactualLiveLoop.PersistOrRunLive(
                dir, id, "lab", payload, StillCrashes, maxProbes: 2, settleSkeptic: false, force: true,
                suspectedOffset: 4);
            Assert.True(first.LiveExecuted);
            var afterFirst = calls;

            var second = CounterfactualLiveLoop.PersistOrRunLive(
                dir, id, "lab", payload, StillCrashes, maxProbes: 2, settleSkeptic: false, force: false,
                suspectedOffset: 4);
            Assert.True(second.LiveExecuted);
            Assert.Equal(afterFirst, calls); // no re-exec
            Assert.Contains("reused", second.Summary, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }
}
