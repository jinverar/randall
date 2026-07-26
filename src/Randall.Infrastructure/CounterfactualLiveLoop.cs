using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Counterfactual live execution loop — Hypothesis → experiments → EXECUTE (target/replay) →
/// observe → update evidence/influence/hypothesis confidence → optional Skeptic settle → persist.
/// Research/teaching only; bounded budget keeps this off the hot-path suicide list.
/// </summary>
public static class CounterfactualLiveLoop
{
    /// <summary>Default probe budget for post-crash live re-exec (not every sweep index).</summary>
    public const int DefaultMaxProbes = 5;

    /// <summary>Max skeptic challenges to settle per live run.</summary>
    public const int DefaultMaxSkepticChallenges = 2;

    /// <summary>
    /// Full execute→observe→persist loop. <paramref name="stillCrashes"/> is the target/replay oracle.
    /// </summary>
    public static CounterfactualLiveResultDto Run(
        string crashesDir,
        Guid crashId,
        string project,
        byte[] payload,
        Func<byte[], bool> stillCrashes,
        int maxProbes = DefaultMaxProbes,
        bool settleSkeptic = true,
        int maxSkepticChallenges = DefaultMaxSkepticChallenges,
        int? suspectedOffset = null,
        CrashInfluenceMapDto? influence = null,
        RootCauseAnalysisDto? rootCause = null,
        CrashCorruptionChainDto? corruption = null,
        HypothesisSetDto? hypotheses = null)
    {
        if (payload.Length == 0)
        {
            var empty = new CounterfactualReportDto(
                false, crashId, project, null,
                "No payload for live counterfactual loop.",
                null, [], 0, 0, "UNKNOWN", DateTimeOffset.UtcNow, Error: "no payload");
            CounterfactualEngine.Write(crashesDir, empty);
            return new CounterfactualLiveResultDto(
                false, empty, hypotheses, influence, null, 0, false,
                empty.Summary, DateTimeOffset.UtcNow, empty.Error);
        }

        influence ??= InfluenceEngine.TryRead(InfluenceEngine.PathFor(crashesDir, crashId));
        rootCause ??= RootCauseEngine.TryRead(RootCauseEngine.PathFor(crashesDir, crashId));
        corruption ??= CorruptionChainBuilder.TryRead(CorruptionChainBuilder.PathFor(crashesDir, crashId));
        hypotheses ??= HypothesisEngine.TryReadForCrash(crashesDir, crashId);

        var report = CounterfactualEngine.Evaluate(
            crashId, project, payload, stillCrashes, suspectedOffset,
            influence, rootCause, corruption, maxProbes);

        var updatedIds = new List<string>();
        if (hypotheses is { Ok: true, Hypotheses.Count: > 0 })
        {
            hypotheses = ApplyHypothesisUpdates(hypotheses, report, updatedIds);
            HypothesisEngine.Write(crashesDir, hypotheses);
            influence = InfluenceEngine.RefreshFromHypotheses(crashesDir, crashId, hypotheses) ?? influence;
        }

        report = report with
        {
            UpdatedHypothesisIds = updatedIds,
            At = DateTimeOffset.UtcNow,
        };
        CounterfactualEngine.Write(crashesDir, report);

        SkepticReportDto? skeptic = null;
        if (settleSkeptic)
        {
            skeptic = SkepticEngine.TryReadForCrash(crashesDir, crashId);
            if (skeptic is null)
            {
                var primitives = PrimitiveEngine.TryReadForCrash(crashesDir, crashId);
                var plan = ResearchPlannerEngine.TryReadForCrash(crashesDir, crashId);
                skeptic = SkepticEngine.PersistForCrash(
                    crashesDir, crashId, project, plan, rootCause, influence, primitives);
            }

            skeptic = SettleSkepticChallenges(
                skeptic, payload, stillCrashes, report.SuspectedOffset, maxSkepticChallenges);
            SkepticEngine.Write(crashesDir, skeptic);
        }

        var summary =
            $"Live loop: {report.ExperimentsExecuted} probe(s) executed · " +
            $"{report.SafeAdjacentCount} safe / {report.StillCorruptCount} corrupt · " +
            $"{updatedIds.Count} hypothesis update(s)" +
            (skeptic is { Ok: true } ? $" · skeptic {CountSettled(skeptic)} settled" : "") +
            ".";

        return new CounterfactualLiveResultDto(
            report.Ok, report, hypotheses, influence, skeptic,
            report.ExperimentsExecuted, report.LiveExecuted, summary, DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Build a sync <c>stillCrashes</c> oracle from <see cref="ReplayEngine"/> (post-crash path).
    /// Exceptions propagate so Evaluate marks the probe Inconclusive.
    /// </summary>
    public static Func<byte[], bool> CreateReplayOracle(
        ProjectConfig project,
        string yamlPath,
        CancellationToken cancellationToken = default)
    {
        var engine = new ReplayEngine();
        return variant =>
        {
            var result = engine.ReplayAsync(project, yamlPath, variant, cancellationToken)
                .ConfigureAwait(false)
                .GetAwaiter()
                .GetResult();
            return result.Crashed;
        };
    }

    /// <summary>
    /// Persist plan-only when no oracle; otherwise run the live loop with a bounded budget.
    /// Skips re-exec when a prior live report already exists (unless <paramref name="force"/>).
    /// </summary>
    public static CounterfactualLiveResultDto PersistOrRunLive(
        string crashesDir,
        Guid crashId,
        string project,
        byte[]? payload,
        Func<byte[], bool>? stillCrashes,
        int maxProbes = DefaultMaxProbes,
        bool settleSkeptic = true,
        bool force = false,
        int? suspectedOffset = null,
        CrashInfluenceMapDto? influence = null,
        RootCauseAnalysisDto? rootCause = null,
        CrashCorruptionChainDto? corruption = null,
        HypothesisSetDto? hypotheses = null)
    {
        if (!force)
        {
            var existing = CounterfactualEngine.TryReadForCrash(crashesDir, crashId);
            if (existing is { LiveExecuted: true, Ok: true })
            {
                return new CounterfactualLiveResultDto(
                    true, existing,
                    hypotheses ?? HypothesisEngine.TryReadForCrash(crashesDir, crashId),
                    influence ?? InfluenceEngine.TryRead(InfluenceEngine.PathFor(crashesDir, crashId)),
                    SkepticEngine.TryReadForCrash(crashesDir, crashId),
                    existing.ExperimentsExecuted, true,
                    "Prior live counterfactual report reused (force=false).",
                    DateTimeOffset.UtcNow);
            }
        }

        if (stillCrashes is null || payload is null || payload.Length == 0)
        {
            var plan = CounterfactualEngine.PersistForCrash(
                crashesDir, crashId, project, payload, stillCrashes: null,
                suspectedOffset, influence, rootCause, corruption);
            return new CounterfactualLiveResultDto(
                plan.Ok, plan, hypotheses, influence, null, 0, false,
                plan.Summary, DateTimeOffset.UtcNow, plan.Error);
        }

        return Run(
            crashesDir, crashId, project, payload, stillCrashes, maxProbes, settleSkeptic,
            DefaultMaxSkepticChallenges, suspectedOffset, influence, rootCause, corruption, hypotheses);
    }

    internal static HypothesisSetDto ApplyHypothesisUpdates(
        HypothesisSetDto set,
        CounterfactualReportDto report,
        List<string> updatedIds)
    {
        if (set.Hypotheses.Count == 0)
            return set;

        var target = set.Hypotheses
            .OrderByDescending(h => h.Status is HypothesisStatus.Pending or HypothesisStatus.Running)
            .ThenByDescending(h => h.ConfidencePercent)
            .First();

        var before = target.ConfidencePercent;
        HypothesisStatus status;
        int after;
        string observation;

        if (report.SmallestSafeChange is not null)
        {
            // Boundary found: offset attribution strengthened.
            status = HypothesisStatus.Partial;
            after = Math.Min(95, before + 12);
            observation =
                $"Counterfactual live: safe-adjacent via {report.SmallestSafeChange.Description} " +
                $"(Δ{report.SmallestSafeChange.ByteDelta})";
        }
        else if (report.StillCorruptCount > 0 && report.SafeAdjacentCount == 0)
        {
            status = HypothesisStatus.Partial;
            after = Math.Min(90, before + 4);
            observation =
                $"Counterfactual live: {report.StillCorruptCount} still-corrupt — local flip did not clear bug";
        }
        else
        {
            status = HypothesisStatus.Inconclusive;
            after = before;
            observation = "Counterfactual live: inconclusive boundary map";
        }

        var updated = target with
        {
            Status = status,
            ConfidencePercent = after,
            Result = new HypothesisResultDto(
                status, after, observation, null, DateTimeOffset.UtcNow, before),
        };
        updatedIds.Add(updated.Id);

        var list = set.Hypotheses
            .Select(h => h.Id.Equals(updated.Id, StringComparison.OrdinalIgnoreCase) ? updated : h)
            .ToList();
        return set with { Hypotheses = list, At = DateTimeOffset.UtcNow };
    }

    internal static SkepticReportDto SettleSkepticChallenges(
        SkepticReportDto report,
        byte[] payload,
        Func<byte[], bool> stillCrashes,
        int? offset,
        int maxChallenges)
    {
        if (!report.Ok || report.Challenges.Count == 0 || maxChallenges <= 0)
            return report;

        var settled = report;
        var count = 0;
        foreach (var challenge in report.Challenges.Where(c => c.Status == SkepticChallengeStatus.Proposed))
        {
            if (count >= maxChallenges)
                break;

            var status = RunSkepticNeutralize(payload, stillCrashes, offset ?? challenge.Experiment.OffsetBytes);
            var observation = status switch
            {
                SkepticChallengeStatus.Survived => "Neutralize/hold replay still faults — claim survived",
                SkepticChallengeStatus.Falsified => "Neutralize/hold cleared the fault — claim falsified",
                _ => "Neutralize/hold inconclusive",
            };
            settled = SkepticEngine.ApplyObservation(settled, challenge.Id, status, observation);
            count++;
        }

        return settled;
    }

    private static SkepticChallengeStatus RunSkepticNeutralize(
        byte[] payload,
        Func<byte[], bool> stillCrashes,
        int? offset)
    {
        try
        {
            var experiment = new HypothesisExperimentDto(
                HypothesisExperimentKind.MinimizeHold,
                "Skeptic neutralize hold-out",
                OffsetBytes: offset ?? 0,
                BudgetIterations: 1);
            var variant = HypothesisEngine.ApplyExperiment(payload, experiment, sweepIndex: 0, new Random(1));
            if (variant is null || variant.Length == 0)
                return SkepticChallengeStatus.Inconclusive;

            // Original must still be crashy for a meaningful neutralize test.
            if (!stillCrashes(payload))
                return SkepticChallengeStatus.Inconclusive;

            var stillFaults = stillCrashes(variant);
            return stillFaults
                ? SkepticChallengeStatus.Survived
                : SkepticChallengeStatus.Falsified;
        }
        catch
        {
            return SkepticChallengeStatus.Inconclusive;
        }
    }

    private static int CountSettled(SkepticReportDto report) =>
        report.Challenges.Count(c => c.Status is SkepticChallengeStatus.Survived
            or SkepticChallengeStatus.Falsified
            or SkepticChallengeStatus.Inconclusive);
}
