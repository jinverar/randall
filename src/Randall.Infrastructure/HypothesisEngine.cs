using System.Text;
using System.Text.Json;
using Randall.Contracts;
using Randall.Core;

namespace Randall.Infrastructure;

/// <summary>
/// Phase C Hypothesis Engine — deterministic testable hypotheses from corruption chain,
/// debugger observation, lineage, scream evolution, and oracle. Queues research-only
/// sweeps/holds; updates confidence when experiments run. No LLM on the hot path.
/// </summary>
public static class HypothesisEngine
{
    public const string QueueFileName = "hypothesis_queue.json";
    public const string LedgerFileName = "ledger.json";
    public const int MinExperimentConfidence = 50;
    public const int MagicianBudgetConfidence = 65;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    public static string LedgerDir(string crashesDir) => Path.Combine(crashesDir, "_hypotheses");
    public static string PathFor(string crashesDir, Guid crashId) => Path.Combine(LedgerDir(crashesDir), $"{crashId:N}.json");
    public static string LegacyPathFor(string crashesDir, Guid crashId) => Path.Combine(crashesDir, $"{crashId:N}_hypotheses.json");
    public static string LedgerPath(string crashesDir) => Path.Combine(LedgerDir(crashesDir), LedgerFileName);

    public static string QueuePath(string project, string? repoRoot = null) =>
        Path.Combine(StalkCampaignStore.ProjectDir(project, repoRoot), QueueFileName);

    public static HypothesisSetDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<HypothesisSetDto>(File.ReadAllText(path), JsonOptions);
        }
        catch
        {
            return null;
        }
    }


    public static HypothesisSetDto? TryReadForCrash(string crashesDir, Guid crashId) =>
        TryRead(PathFor(crashesDir, crashId)) ?? TryRead(LegacyPathFor(crashesDir, crashId));

    public static HypothesisProjectLedgerDto? TryLoadLedger(string crashesDir)
    {
        var path = LedgerPath(crashesDir);
        if (!File.Exists(path)) return null;
        try { return JsonSerializer.Deserialize<HypothesisProjectLedgerDto>(File.ReadAllText(path), JsonOptions); }
        catch { return null; }
    }

    public static void SyncProjectLedger(string project, string crashesDir, int iteration, string? repoRoot = null)
    {
        var queue = TryLoadQueue(project, repoRoot);
        var entries = new List<HypothesisLedgerEntryDto>();
        HypothesisDto? topPending = null;
        foreach (var set in EnumerateProjectSets(crashesDir))
        {
            if (set?.Hypotheses is not { Count: > 0 }) continue;
            foreach (var h in set.Hypotheses)
            {
                if (entries.Any(e => e.HypothesisId.Equals(h.Id, StringComparison.OrdinalIgnoreCase) && e.CrashId == set.CrashId))
                    continue;
                entries.Add(new HypothesisLedgerEntryDto(h.Id, set.CrashId, h.Statement, h.ConfidencePercent, h.Status, h.Experiment.Kind, h.Result, set.At));
            }
            var top = TopPending(set);
            if (top is not null && (topPending is null || top.ConfidencePercent > topPending.ConfidencePercent))
                topPending = top;
        }
        entries = entries.OrderByDescending(e => e.ConfidencePercent).ThenBy(e => e.HypothesisId, StringComparer.Ordinal).ToList();
        Directory.CreateDirectory(LedgerDir(crashesDir));
        File.WriteAllText(LedgerPath(crashesDir), JsonSerializer.Serialize(
            new HypothesisProjectLedgerDto(project, iteration, DateTimeOffset.UtcNow, entries, topPending, queue), JsonOptions));
    }

    private static IEnumerable<HypothesisSetDto> EnumerateProjectSets(string crashesDir)
    {
        var seen = new HashSet<Guid>();
        var hypDir = LedgerDir(crashesDir);
        if (Directory.Exists(hypDir))
        {
            foreach (var file in Directory.EnumerateFiles(hypDir, "*.json"))
            {
                if (Path.GetFileName(file).Equals(LedgerFileName, StringComparison.OrdinalIgnoreCase)) continue;
                var set = TryRead(file);
                if (set is not null && seen.Add(set.CrashId)) yield return set;
            }
        }
        if (!Directory.Exists(crashesDir)) yield break;
        foreach (var file in Directory.EnumerateFiles(crashesDir, "*_hypotheses.json"))
        {
            var set = TryRead(file);
            if (set is not null && seen.Add(set.CrashId)) yield return set;
        }
    }

    public static HypothesisSetDto Build(
        Guid crashId,
        string project,
        CrashSidecarDto? sidecar,
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? corruptionChain,
        ScreamEvolutionDto? evolution,
        OracleScore? oracleScore = null,
        CrashBackwardTraceDto? backwardTrace = null)
    {
        var hypotheses = new List<HypothesisDto>();
        var evidence = CollectEvidence(sidecar, triage, debugger, corruptionChain, evolution, oracleScore, backwardTrace);

        AddPatternDepthHypotheses(hypotheses, crashId, corruptionChain, debugger, sidecar, evidence);
        AddLineageHypotheses(hypotheses, crashId, corruptionChain, evolution, sidecar, evidence);
        AddDebuggerHypotheses(hypotheses, crashId, debugger, corruptionChain, sidecar, evidence);
        AddBackwardTraceHypotheses(hypotheses, crashId, backwardTrace, corruptionChain, sidecar, evidence);
        AddOracleHypotheses(hypotheses, crashId, oracleScore, sidecar, corruptionChain, evidence);
        AddStagnationHypotheses(hypotheses, crashId, evolution, sidecar, corruptionChain, evidence);

        var ranked = hypotheses
            .OrderByDescending(h => h.ConfidencePercent)
            .ThenBy(h => h.Id, StringComparer.Ordinal)
            .ToList();

        return new HypothesisSetDto(
            ranked.Count > 0,
            crashId,
            project,
            ranked,
            DateTimeOffset.UtcNow);
    }

    public static HypothesisSetDto PersistForCrash(
        string crashesDir,
        Guid crashId,
        string project,
        CrashSidecarDto? sidecar,
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? corruptionChain,
        ScreamEvolutionDto? evolution,
        OracleScore? oracleScore = null,
        CrashBackwardTraceDto? backwardTrace = null)
    {
        var set = Build(crashId, project, sidecar, triage, debugger, corruptionChain, evolution, oracleScore, backwardTrace);
        Write(crashesDir, set);
        return set;
    }

    public static string Write(string crashesDir, HypothesisSetDto set)
    {
        Directory.CreateDirectory(LedgerDir(crashesDir));
        var path = PathFor(crashesDir, set.CrashId);
        File.WriteAllText(path, JsonSerializer.Serialize(set, JsonOptions));
        SyncProjectLedger(set.Project, crashesDir, TryLoadQueue(set.Project)?.Iteration ?? 0);
        return path;
    }

    public static HypothesisDto? TopPending(HypothesisSetDto? set) =>
        set?.Hypotheses.FirstOrDefault(h => h.Status is HypothesisStatus.Pending or HypothesisStatus.Running);

    public static HypothesisDto? FindTopForProject(string project, string? repoRoot = null)
    {
        var repo = repoRoot ?? CrashCatalog.FindRepoRoot();
        if (repo is null)
            return null;

        var crashesDir = Path.Combine(repo, "data", "crashes", project);
        if (!Directory.Exists(crashesDir))
            return null;

        HypothesisDto? best = null;
        foreach (var set in EnumerateProjectSets(crashesDir))
        {
            var top = TopPending(set);
            if (top is null) continue;
            if (best is null || top.ConfidencePercent > best.ConfidencePercent) best = top;
        }

        var snap = TryLoadQueue(project, repoRoot);
        if (snap?.TopHypothesis is { Status: HypothesisStatus.Pending or HypothesisStatus.Running } queued
            && (best is null || queued.ConfidencePercent > best.ConfidencePercent))
            return queued;

        return best;
    }


    public static bool MarkRunning(string crashesDir, Guid crashId, string hypothesisId)
    {
        var set = TryReadForCrash(crashesDir, crashId);
        if (set is null) return false;
        var hyp = set.Hypotheses.FirstOrDefault(h => h.Id.Equals(hypothesisId, StringComparison.OrdinalIgnoreCase));
        if (hyp is null || hyp.Status is not HypothesisStatus.Pending) return false;
        var updated = hyp with { Status = HypothesisStatus.Running };
        Write(crashesDir, set with { Hypotheses = set.Hypotheses.Select(h => h.Id.Equals(updated.Id, StringComparison.OrdinalIgnoreCase) ? updated : h).ToList() });
        return true;
    }

    public static void EnqueueFromHypothesis(
        string project,
        HypothesisDto hypothesis,
        int iteration,
        string? repoRoot = null)
    {
        if (hypothesis.Status is not (HypothesisStatus.Pending or HypothesisStatus.Running))
            return;
        if (hypothesis.ConfidencePercent < MinExperimentConfidence)
            return;
        if (hypothesis.CrashId is not Guid crashId)
            return;

        var snap = TryLoadQueue(project, repoRoot) ?? new HypothesisProjectSnapshotDto(
            project, iteration, DateTimeOffset.UtcNow, [], null);

        var queue = snap.Queue.ToList();
        if (queue.Any(q => q.HypothesisId.Equals(hypothesis.Id, StringComparison.OrdinalIgnoreCase)))
            return;

        queue.Add(new HypothesisQueueEntryDto(
            hypothesis.Id,
            crashId,
            project,
            hypothesis.Experiment,
            hypothesis.ConfidencePercent,
            hypothesis.Experiment.BudgetIterations,
            SweepIndex: 0,
            DateTimeOffset.UtcNow));

        queue = queue
            .OrderByDescending(q => q.ConfidencePercent)
            .ThenBy(q => q.QueuedAt)
            .Take(8)
            .ToList();

        PersistQueue(project, iteration, queue, hypothesis, repoRoot);
    }

    public static HypothesisExperimentPlan? TryDequeuePlan(string project, string? repoRoot = null)
    {
        var snap = TryLoadQueue(project, repoRoot);
        if (snap?.Queue.Count is not > 0)
            return null;

        var entry = snap.Queue[0];
        if (entry.RemainingBudget <= 0)
        {
            RemoveQueueEntry(project, entry.HypothesisId, repoRoot);
            return TryDequeuePlan(project, repoRoot);
        }

        var repo = repoRoot ?? CrashCatalog.FindRepoRoot();
        var crashesDir = repo is null
            ? null
            : Path.Combine(repo, "data", "crashes", project);
        var inputPath = crashesDir is null
            ? null
            : FindCrashInputPath(crashesDir, entry.CrashId);

        if (crashesDir is not null)
            MarkRunning(crashesDir, entry.CrashId, entry.HypothesisId);

        return new HypothesisExperimentPlan(
            entry.HypothesisId,
            entry.CrashId,
            project,
            entry.Experiment,
            entry.ConfidencePercent,
            entry.SweepIndex,
            inputPath,
            entry.RemainingBudget);
    }

    public static byte[]? ApplyExperiment(byte[] basePayload, HypothesisExperimentDto experiment, int sweepIndex, Random rng, IReadOnlyList<IMutator>? mutators = null)
    {
        if (basePayload.Length == 0) return null;
        return experiment.Kind switch
        {
            HypothesisExperimentKind.SweepOffset => ApplySweepOffset(basePayload, experiment, sweepIndex),
            HypothesisExperimentKind.BoundaryProbe => ApplyBoundaryProbe(basePayload, experiment, sweepIndex),
            HypothesisExperimentKind.MinimizeHold => ApplyMinimizeHold(basePayload, experiment),
            HypothesisExperimentKind.ReplayLineage => ApplyReplayLineage(basePayload, experiment, sweepIndex, mutators),
            HypothesisExperimentKind.HoldMutator => ApplyHoldMutator(basePayload, experiment, sweepIndex, rng, mutators),
            _ => basePayload.ToArray(),
        };
    }

    public static void RecordOutcome(
        string project,
        HypothesisExperimentPlan plan,
        int iteration,
        bool crashed,
        string? crashClass,
        string? faultDetail,
        string? repoRoot = null)
    {
        var repo = repoRoot ?? CrashCatalog.FindRepoRoot();
        if (repo is null)
            return;

        var crashesDir = Path.Combine(repo, "data", "crashes", project);
        var set = TryReadForCrash(crashesDir, plan.CrashId);
        if (set is null)
            return;

        var hyp = set.Hypotheses.FirstOrDefault(h =>
            h.Id.Equals(plan.HypothesisId, StringComparison.OrdinalIgnoreCase));
        if (hyp is null)
            return;

        var confidenceBefore = hyp.ConfidencePercent;
        var remainingAfter = plan.RemainingBudget - 1;
        var (status, confidence, observation) = EvaluateOutcome(hyp, crashed, crashClass, faultDetail, remainingAfter);

        var updated = hyp with
        {
            Status = status,
            ConfidencePercent = confidence,
            Result = new HypothesisResultDto(status, confidence, observation, iteration, DateTimeOffset.UtcNow, confidenceBefore),
        };

        var hypotheses = set.Hypotheses
            .Select(h => h.Id.Equals(updated.Id, StringComparison.OrdinalIgnoreCase) ? updated : h)
            .ToList();
        Write(crashesDir, set with { Hypotheses = hypotheses });
        InfluenceEngine.RefreshFromHypotheses(crashesDir, plan.CrashId, set with { Hypotheses = hypotheses });

        var snap = TryLoadQueue(project, repoRoot);
        if (snap?.Queue.Count is not > 0)
            return;

        var entry = snap.Queue.FirstOrDefault(q =>
            q.HypothesisId.Equals(plan.HypothesisId, StringComparison.OrdinalIgnoreCase));
        if (entry is null)
            return;

        var remaining = remainingAfter;
        if (remaining <= 0 || status is HypothesisStatus.Confirmed or HypothesisStatus.Refuted)
        {
            RemoveQueueEntry(project, plan.HypothesisId, repoRoot);
            return;
        }

        var queue = snap.Queue.ToList();
        var idx = queue.FindIndex(q => q.HypothesisId.Equals(plan.HypothesisId, StringComparison.OrdinalIgnoreCase));
        if (idx >= 0)
        {
            queue[idx] = entry with
            {
                RemainingBudget = remaining,
                SweepIndex = entry.SweepIndex + 1,
            };
            PersistQueue(project, iteration, queue, updated, repoRoot);
        }
    }

    public static HypothesisProjectSnapshotDto? TryLoadQueue(string project, string? repoRoot = null)
    {
        var path = QueuePath(project, repoRoot);
        if (!File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<HypothesisProjectSnapshotDto>(File.ReadAllText(path), JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    public static void PersistQueue(
        string project,
        int iteration,
        IReadOnlyList<HypothesisQueueEntryDto> queue,
        HypothesisDto? topHypothesis,
        string? repoRoot = null)
    {
        var path = QueuePath(project, repoRoot);
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        var snap = new HypothesisProjectSnapshotDto(
            project, iteration, DateTimeOffset.UtcNow, queue, topHypothesis);
        File.WriteAllText(path, JsonSerializer.Serialize(snap, JsonOptions));

        var repo = repoRoot ?? CrashCatalog.FindRepoRoot();
        if (repo is not null)
        {
            var crashesDir = Path.Combine(repo, "data", "crashes", project);
            if (Directory.Exists(crashesDir))
                SyncProjectLedger(project, crashesDir, iteration, repoRoot);
        }
    }

    public static string FormatVerbose(HypothesisDto hypothesis) =>
        $"Hypothesis [{hypothesis.ConfidencePercent}%] {hypothesis.Id}: {hypothesis.Statement} " +
        $"→ {hypothesis.Experiment.Kind} ({hypothesis.Experiment.Description})";

    public static string AppendMagicianHint(
        string magicianDir,
        HypothesisDto hypothesis,
        int iteration,
        string? experimentHint = null)
    {
        Directory.CreateDirectory(magicianDir);
        var path = Path.Combine(magicianDir, "rewind_scream_hint.md");
        var sb = new StringBuilder();
        sb.AppendLine($"[{DateTimeOffset.UtcNow:u}] iter={iteration} · **hypothesis** `{hypothesis.Id}` ({hypothesis.ConfidencePercent}%)");
        sb.AppendLine($"  {hypothesis.Statement}");
        sb.AppendLine($"  experiment: {hypothesis.Experiment.Kind} — {hypothesis.Experiment.Description}");
        sb.AppendLine($"  expect: {hypothesis.ExpectedObservation}");
        if (!string.IsNullOrWhiteSpace(experimentHint))
            sb.AppendLine($"  hunt: {experimentHint}");
        sb.AppendLine("  Phase D: live TTD rewind remains external (stub only).");
        sb.AppendLine();
        File.AppendAllText(path, sb.ToString());
        return path;
    }

    private static void AddPatternDepthHypotheses(
        List<HypothesisDto> list,
        Guid crashId,
        CrashCorruptionChainDto? chain,
        DebuggerObservation? debugger,
        CrashSidecarDto? sidecar,
        List<string> evidence)
    {
        if (chain?.PatternDepthBytes is not int offset)
            return;

        var access = debugger?.Access is DebuggerAccessKind.Write or DebuggerAccessKind.Execute
            ? debugger.Access.ToString()
            : "fault";
        var mutator = chain.SuspectedMutator ?? sidecar?.Mutator ?? "havoc";
        var confidence = ScoreBase(chain.Confidence) + 12;
        if (debugger?.SuspectedInputInfluence.Equals("HIGH", StringComparison.OrdinalIgnoreCase) == true)
            confidence += 8;

        list.Add(new HypothesisDto(
            $"hyp-offset-{offset:X}",
            crashId,
            $"Input byte at offset {offset} (0x{offset:X}) influences {access} fault — {chain.SuspectedField ?? "payload field"}",
            Math.Clamp(confidence, 35, 92),
            new HypothesisExperimentDto(
                HypothesisExperimentKind.SweepOffset,
                $"Sweep ±{Math.Min(8, Math.Max(2, offset / 8 + 2))} bytes around offset {offset}",
                "bitflip",
                offset,
                Math.Min(8, Math.Max(2, offset / 8 + 2)),
                chain.MutatorLineage,
                sidecar?.Command),
            $"Same crash class with fault address tracking sweep index; refuted if crash disappears at offset",
            HypothesisStatus.Pending,
            Evidence: evidence));

        if (offset >= 4)
        {
            list.Add(new HypothesisDto(
                $"hyp-boundary-{offset:X}",
                crashId,
                $"Boundary values at offset {offset} drive {access} — probe interesting integers/lengths",
                Math.Clamp(confidence - 8, 30, 85),
                new HypothesisExperimentDto(
                    HypothesisExperimentKind.BoundaryProbe,
                    $"Probe 0, MAX-1, MAX at offset {offset}",
                    "interesting",
                    offset,
                    Command: sidecar?.Command),
                $"Crash reproduces with 0xFFFFFFFF or zero at offset; partial if only some values trigger",
                HypothesisStatus.Pending,
                Evidence: evidence));
        }
    }

    private static void AddLineageHypotheses(
        List<HypothesisDto> list,
        Guid crashId,
        CrashCorruptionChainDto? chain,
        ScreamEvolutionDto? evolution,
        CrashSidecarDto? sidecar,
        List<string> evidence)
    {
        var lineage = chain?.MutatorLineage?.ToList()
                      ?? sidecar?.MutatorChain?.ToList()
                      ?? [];
        if (lineage.Count < 2)
            return;

        var mutator = lineage[^1];
        var confidence = 48 + Math.Min(20, lineage.Count * 4);
        if (evolution?.MomentumScore >= 40)
            confidence += 10;
        if (evolution?.Generation >= 2)
            confidence += 6;

        list.Add(new HypothesisDto(
            $"hyp-lineage-{mutator}",
            crashId,
            $"Mutator '{mutator}' on lineage {string.Join("→", lineage)} is causal for scream family {evolution?.FamilyId ?? chain?.Summary ?? "cluster"}",
            Math.Clamp(confidence, 40, 88),
            new HypothesisExperimentDto(
                HypothesisExperimentKind.ReplayLineage,
                $"Replay chain {string.Join("→", lineage)} from seed",
                mutator,
                MutatorChain: lineage,
                Command: sidecar?.Command),
            $"Replay reproduces crash class; refuted if alternate terminal mutator yields same fault",
            HypothesisStatus.Pending,
            Evidence: evidence));

        list.Add(new HypothesisDto(
            $"hyp-hold-{mutator}",
            crashId,
            $"Holding mutator '{mutator}' on crash input preserves fault — minimize elsewhere",
            Math.Clamp(confidence - 5, 38, 82),
            new HypothesisExperimentDto(
                HypothesisExperimentKind.HoldMutator,
                $"Hold {mutator} on crash input, havoc elsewhere",
                mutator,
                MutatorChain: lineage,
                Command: sidecar?.Command),
            $"Crash persists with held mutator; confidence rises if minimize-hold keeps fault",
            HypothesisStatus.Pending,
            Evidence: evidence));
    }

    private static void AddDebuggerHypotheses(
        List<HypothesisDto> list,
        Guid crashId,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? chain,
        CrashSidecarDto? sidecar,
        List<string> evidence)
    {
        if (debugger is not { Ok: true })
            return;

        if (debugger.FaultAddressClass == DebuggerAddressClass.AsciiPattern
            && chain?.PatternDepthBytes is int off)
        {
            list.Add(new HypothesisDto(
                $"hyp-ascii-{off:X}",
                crashId,
                $"Fault address matches ASCII/pattern at input offset {off} — controlled pointer from payload",
                Math.Clamp(ScoreBase(chain.Confidence) + 15, 45, 90),
                new HypothesisExperimentDto(
                    HypothesisExperimentKind.MinimizeHold,
                    $"Preserve bytes [{off},{off + 4}) while shrinking tail",
                    chain.SuspectedMutator ?? "expand",
                    off,
                    SweepRange: 4,
                    Command: sidecar?.Command),
                $"Minimized input still crashes with same fault address class",
                HypothesisStatus.Pending,
                Evidence: evidence));
        }

        if (debugger.Access == DebuggerAccessKind.Write
            && evolutionProgressionWarming(debugger, chain))
        {
            list.Add(new HypothesisDto(
                "hyp-write-progression",
                crashId,
                $"Write violation at {debugger.FaultingFunction ?? "fault site"} — breeding may reach controlled write",
                Math.Clamp(55 + debugger.DebuggerScreamBonus / 5, 45, 85),
                new HypothesisExperimentDto(
                    HypothesisExperimentKind.HoldMutator,
                    "Hold expand/cyclic on warming lineage input",
                    chain?.SuspectedMutator ?? "cyclic",
                    MutatorChain: chain?.MutatorLineage,
                    Command: sidecar?.Command),
                $"Same family with equal or higher progression step (write → controlled write)",
                HypothesisStatus.Pending,
                Evidence: evidence));
        }
    }

    private static void AddOracleHypotheses(
        List<HypothesisDto> list,
        Guid crashId,
        OracleScore? oracleScore,
        CrashSidecarDto? sidecar,
        CrashCorruptionChainDto? chain,
        List<string> evidence)
    {
        if (oracleScore is not { Total: >= 35 })
            return;

        var term = oracleScore.Terms.FirstOrDefault(t => t.Points >= 10);
        var label = term?.Label ?? "oracle signal";
        list.Add(new HypothesisDto(
            "hyp-oracle-correlate",
            crashId,
            $"Oracle '{label}' correlates with mutator '{chain?.SuspectedMutator ?? sidecar?.Mutator ?? "?"}' on command '{sidecar?.Command ?? "default"}'",
            Math.Clamp(40 + oracleScore.Total / 4, 40, 78),
            new HypothesisExperimentDto(
                HypothesisExperimentKind.ReplayLineage,
                "Replay crash input with dictionary/interesting pressure",
                "interesting",
                MutatorChain: chain?.MutatorLineage ?? sidecar?.MutatorChain,
                Command: sidecar?.Command),
            $"Oracle score ≥ prior on replay; partial if near-miss without crash",
            HypothesisStatus.Pending,
            Evidence: evidence));
    }

    private static void AddStagnationHypotheses(
        List<HypothesisDto> list,
        Guid crashId,
        ScreamEvolutionDto? evolution,
        CrashSidecarDto? sidecar,
        CrashCorruptionChainDto? chain,
        List<string> evidence)
    {
        if (evolution is not { Ok: true, Generation: >= 2, MomentumScore: >= 35 and < 50 })
            return;

        list.Add(new HypothesisDto(
            $"hyp-stall-{evolution.FamilyId}",
            crashId,
            $"Stalled warming family '{evolution.FamilyId}' gen {evolution.Generation} — corruption chain experiment may unlock progression",
            Math.Clamp(52 + evolution.Generation * 2, 48, 75),
            new HypothesisExperimentDto(
                HypothesisExperimentKind.SweepOffset,
                chain?.PatternDepthBytes is int o
                    ? $"Sweep around pattern depth {o} on lineage input"
                    : "Replay lineage with splice/havoc hold",
                chain?.SuspectedMutator ?? "splice",
                chain?.PatternDepthBytes,
                chain?.PatternDepthBytes is int r ? 6 : null,
                chain?.MutatorLineage,
                sidecar?.Command),
            $"Momentum rises above {evolution.MomentumScore} or progression step advances",
            HypothesisStatus.Pending,
            Evidence: evidence));
    }

    private static void AddBackwardTraceHypotheses(
        List<HypothesisDto> list,
        Guid crashId,
        CrashBackwardTraceDto? trace,
        CrashCorruptionChainDto? chain,
        CrashSidecarDto? sidecar,
        List<string> evidence)
    {
        if (trace is not { Ok: true })
            return;

        if (trace.FaultRegister is not null && trace.PrimaryPayloadOffset is not null)
        {
            list.Add(new HypothesisDto(
                $"hyp-btrace-reg-{trace.FaultRegister.ToLowerInvariant()}",
                crashId,
                $"Backward trace: {trace.FaultRegister} from payload{trace.PrimaryPayloadOffset} drives fault — mutation '{trace.SuspectedMutator ?? chain?.SuspectedMutator ?? "?"}'",
                Math.Clamp(ScoreBase(trace.Confidence) + 10, 45, 90),
                new HypothesisExperimentDto(
                    HypothesisExperimentKind.ReplayLineage,
                    $"Replay lineage preserving payload{trace.PrimaryPayloadOffset}",
                    trace.SuspectedMutator ?? chain?.SuspectedMutator ?? "havoc",
                    MutatorChain: chain?.MutatorLineage,
                    Command: sidecar?.Command),
                $"Replay reproduces same {trace.FaultRegister} value at fault",
                HypothesisStatus.Pending,
                Evidence: evidence));
        }

        if (trace.HeapTimeline is not null)
        {
            list.Add(new HypothesisDto(
                "hyp-btrace-heap",
                crashId,
                $"Heap timeline ({trace.HeapTimeline}) — UAF/corruption hypothesis from dump probes",
                Math.Clamp(ScoreBase(trace.Confidence) + 5, 40, 82),
                new HypothesisExperimentDto(
                    HypothesisExperimentKind.HoldMutator,
                    "Hold heap-touching mutator; vary alloc pattern elsewhere",
                    trace.SuspectedMutator ?? chain?.SuspectedMutator ?? "havoc",
                    MutatorChain: chain?.MutatorLineage,
                    Command: sidecar?.Command),
                $"Same heap signal on replay; refuted if fault class changes without heap involvement",
                HypothesisStatus.Pending,
                Evidence: evidence));
        }

        if (!string.IsNullOrWhiteSpace(trace.BadPointerSource))
        {
            list.Add(new HypothesisDto(
                "hyp-btrace-source",
                crashId,
                $"Bad pointer source: {trace.BadPointerSource} — {trace.Story}",
                Math.Clamp(ScoreBase(trace.Confidence), 38, 85),
                new HypothesisExperimentDto(
                    HypothesisExperimentKind.MinimizeHold,
                    "Preserve attributed bytes; shrink unrelated payload",
                    trace.SuspectedMutator ?? chain?.SuspectedMutator ?? "expand",
                    chain?.PatternDepthBytes,
                    Command: sidecar?.Command),
                $"Minimized crash retains backward trace story and fault register",
                HypothesisStatus.Pending,
                Evidence: evidence));
        }
    }

    private static List<string> CollectEvidence(
        CrashSidecarDto? sidecar,
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? chain,
        ScreamEvolutionDto? evolution,
        OracleScore? oracleScore,
        CrashBackwardTraceDto? backwardTrace = null)
    {
        var evidence = new List<string>();
        if (chain is { Ok: true })
            evidence.Add($"corruption:{chain.Confidence}");
        if (backwardTrace is { Ok: true })
            evidence.Add($"backwardTrace:{backwardTrace.Confidence}");
        if (debugger is { Ok: true })
            evidence.Add($"debugger:{debugger.Access}/{debugger.FaultAddressClass}");
        if (evolution is { Ok: true })
            evidence.Add($"evolution:{evolution.MomentumLabel} gen={evolution.Generation}");
        if (sidecar?.MutatorChain?.Count > 0)
            evidence.Add($"lineage:{string.Join("→", sidecar.MutatorChain)}");
        if (oracleScore is { Total: > 0 })
            evidence.Add($"oracle:{oracleScore.Total}");
        if (triage?.PatternDepthBytes is int d)
            evidence.Add($"patternDepth:{d}");
        return evidence;
    }

    /// <summary>Merge influence-map evidence tags when the sidecar exists on disk.</summary>
    public static List<string> CollectEvidenceWithInfluence(
        string crashesDir,
        Guid crashId,
        CrashSidecarDto? sidecar,
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? chain,
        ScreamEvolutionDto? evolution,
        OracleScore? oracleScore,
        CrashBackwardTraceDto? backwardTrace = null)
    {
        var evidence = CollectEvidence(sidecar, triage, debugger, chain, evolution, oracleScore, backwardTrace);
        var influence = InfluenceEngine.TryRead(InfluenceEngine.PathFor(crashesDir, crashId));
        if (influence is { Ok: true })
        {
            evidence.Add($"influence:{influence.Confidence}");
            foreach (var link in influence.Links.Take(3))
                evidence.Add($"influenceLink:{link.Status}:{link.Mechanism}");
        }
        return evidence;
    }

    private static int ScoreBase(string? confidenceLabel) =>
        confidenceLabel?.ToUpperInvariant() switch
        {
            "HIGH" => 72,
            "MEDIUM" => 55,
            "LOW" => 38,
            _ => 45,
        };

    private static bool evolutionProgressionWarming(DebuggerObservation debugger, CrashCorruptionChainDto? chain) =>
        debugger.Access == DebuggerAccessKind.Write
        || chain?.Steps.Any(s => s.Kind == "access" && s.Label.Contains("Write", StringComparison.OrdinalIgnoreCase)) == true;

    private static byte[] ApplySweepOffset(byte[] payload, HypothesisExperimentDto experiment, int sweepIndex)
    {
        if (experiment.OffsetBytes is not int center)
            return payload.ToArray();

        var range = experiment.SweepRange ?? 4;
        var offset = center + (sweepIndex % (range * 2 + 1)) - range;
        offset = Math.Clamp(offset, 0, payload.Length - 1);

        var copy = payload.ToArray();
        copy[offset] ^= (byte)(1 << (sweepIndex % 8));
        return copy;
    }


    private static byte[] ApplyReplayLineage(byte[] payload, HypothesisExperimentDto experiment, int sweepIndex, IReadOnlyList<IMutator>? mutators)
    {
        if (sweepIndex <= 0 || mutators is null || experiment.MutatorChain is not { Count: > 0 } chain) return payload.ToArray();
        var result = payload.ToArray();
        for (var i = 0; i < Math.Min(sweepIndex, chain.Count); i++)
        {
            var mut = mutators.FirstOrDefault(m => m.Name.Equals(chain[i], StringComparison.OrdinalIgnoreCase));
            if (mut is not null) result = mut.Mutate(result).ToArray();
        }
        return result;
    }

    private static byte[] ApplyHoldMutator(byte[] payload, HypothesisExperimentDto experiment, int sweepIndex, Random rng, IReadOnlyList<IMutator>? mutators)
    {
        var copy = payload.ToArray();
        IMutator? holdMut = null;
        IMutator? havocMut = null;
        if (mutators is not null)
        {
            if (!string.IsNullOrWhiteSpace(experiment.Mutator))
                holdMut = mutators.FirstOrDefault(m => m.Name.Equals(experiment.Mutator, StringComparison.OrdinalIgnoreCase));
            havocMut = mutators.FirstOrDefault(m => m.Name.Equals("havoc", StringComparison.OrdinalIgnoreCase))
                ?? mutators.FirstOrDefault(m => holdMut is null || !m.Name.Equals(holdMut.Name, StringComparison.OrdinalIgnoreCase));
        }
        if (sweepIndex == 0 && holdMut is not null) copy = holdMut.Mutate(copy).ToArray();
        else if (havocMut is not null) copy = havocMut.Mutate(copy).ToArray();
        if (copy.Length > 0) copy[sweepIndex % copy.Length] ^= (byte)(1 << (sweepIndex % 8));
        return copy;
    }

    private static byte[] ApplyBoundaryProbe(byte[] payload, HypothesisExperimentDto experiment, int sweepIndex)
    {
        if (experiment.OffsetBytes is not int offset || offset + 4 > payload.Length) return payload.ToArray();
        var copy = payload.ToArray();
        var probe = sweepIndex switch
        {
            0 => new byte[] { 0x00, 0x00, 0x00, 0x00 },
            1 => new byte[] { 0xFF, 0xFF, 0xFF, 0xFE },
            _ => new byte[] { 0xFF, 0xFF, 0xFF, 0xFF },
        };
        Buffer.BlockCopy(probe, 0, copy, offset, 4);
        return copy;
    }

    private static byte[] ApplyMinimizeHold(byte[] payload, HypothesisExperimentDto experiment)
    {
        if (experiment.OffsetBytes is not int holdStart)
            return payload.ToArray();

        var holdLen = Math.Min(experiment.SweepRange ?? 4, payload.Length - holdStart);
        if (holdLen <= 0)
            return payload.ToArray();

        var targetLen = Math.Max(holdStart + holdLen + 8, payload.Length / 2);
        targetLen = Math.Min(targetLen, payload.Length);
        if (targetLen >= payload.Length)
            return payload.ToArray();

        var copy = new byte[targetLen];
        Buffer.BlockCopy(payload, 0, copy, 0, targetLen);
        return copy;
    }

    private static (HypothesisStatus Status, int Confidence, string Observation) EvaluateOutcome(
        HypothesisDto hyp, bool crashed, string? crashClass, string? faultDetail, int remainingBudgetAfter)
    {
        var confidence = hyp.ConfidencePercent;
        if (!crashed)
        {
            if (remainingBudgetAfter <= 0)
                return (HypothesisStatus.Refuted, Math.Max(10, confidence - 20), "No crash — hypothesis refuted after budget exhausted");
            return (HypothesisStatus.Inconclusive, Math.Max(15, confidence - 12), "No crash — hypothesis weakened (may need different sweep index)");
        }
        var confirmed = hyp.Experiment.Kind switch
        {
            HypothesisExperimentKind.SweepOffset => faultDetail is not null,
            HypothesisExperimentKind.BoundaryProbe => crashClass?.Contains("ACCESS", StringComparison.OrdinalIgnoreCase) == true,
            HypothesisExperimentKind.MinimizeHold => true,
            HypothesisExperimentKind.ReplayLineage or HypothesisExperimentKind.HoldMutator => true,
            _ => true,
        };
        if (confirmed)
        {
            confidence = Math.Min(95, confidence + 8);
            return (HypothesisStatus.Confirmed, confidence, $"Crash reproduced: {faultDetail ?? crashClass ?? "runtime fault"}");
        }
        if (remainingBudgetAfter <= 0)
            return (HypothesisStatus.Refuted, Math.Max(15, confidence - 10), $"Crash with different signature — refuted: {faultDetail ?? crashClass}");
        confidence = Math.Max(20, confidence - 5);
        return (HypothesisStatus.Partial, confidence, $"Crash with different signature: {faultDetail ?? crashClass}");
    }

    private static void RemoveQueueEntry(string project, string hypothesisId, string? repoRoot)
    {
        var snap = TryLoadQueue(project, repoRoot);
        if (snap is null)
            return;

        var queue = snap.Queue
            .Where(q => !q.HypothesisId.Equals(hypothesisId, StringComparison.OrdinalIgnoreCase))
            .ToList();
        PersistQueue(project, snap.Iteration, queue, snap.TopHypothesis, repoRoot);
    }

    private static string? FindCrashInputPath(string crashesDir, Guid crashId)
    {
        if (!Directory.Exists(crashesDir))
            return null;

        foreach (var file in Directory.EnumerateFiles(crashesDir, "*.bin"))
        {
            if (file.Contains(crashId.ToString("N"), StringComparison.OrdinalIgnoreCase))
                return file;
        }
        return null;
    }
}

/// <summary>Active hypothesis experiment plan for one fuzz iteration.</summary>
public sealed record HypothesisExperimentPlan(
    string HypothesisId,
    Guid CrashId,
    string Project,
    HypothesisExperimentDto Experiment,
    int ConfidencePercent,
    int SweepIndex,
    string? CrashInputPath,
    int RemainingBudget = 3);
