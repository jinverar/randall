using System.Text;
using System.Text.Json;
using Randall.Contracts;
using Randall.Core;

namespace Randall.Infrastructure;

/// <summary>
/// Phase C Hypothesis Engine — deterministic testable hypotheses from corruption chain,
/// debugger observation, lineage, scream evolution, and oracle. Queues research-only
/// sweeps/holds; updates support scores when experiments run. No LLM on the hot path.
/// Schema v2: instance Guid ≠ type id; confirmation via ExpectedPredicate + FaultComparison.
/// </summary>
public static class HypothesisEngine
{
    public const string QueueFileName = "hypothesis_queue.json";
    public const string LedgerFileName = "ledger.json";
    public const int MinExperimentConfidence = 50;
    public const int MagicianBudgetConfidence = 65;
    public const int CurrentSchemaVersion = 2;

    /// <summary>MutatorCorrelation campaign gates (P1).</summary>
    public const int MutatorCorrelationMinExecutions = 20;
    public const int MutatorCorrelationMinCrashes = 3;

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
        var set = ResearchSidecarIO.TryRead<HypothesisSetDto>(path, JsonOptions);
        return set is null ? null : MigrateIfNeeded(set);
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
                entries.Add(new HypothesisLedgerEntryDto(
                    h.Id, set.CrashId, h.Statement, h.ConfidencePercent, h.Status, h.Experiment.Kind, h.Result, set.At,
                    h.TypeId, h.Kind, h.SupportGrade));
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
        CrashBackwardTraceDto? backwardTrace = null,
        ArtifactValidationResult? artifactValidation = null,
        IReadOnlyList<EvidenceFact>? evidenceFacts = null)
    {
        var manifest = BuildManifest(debugger, artifactValidation, corruptionChain);
        var baseline = CaptureBaselineFault(sidecar, debugger, evolution, artifactValidation, manifest);
        var evidenceRefs = CollectEvidenceRefs(evidenceFacts, sidecar, triage, debugger, corruptionChain, evolution, oracleScore, backwardTrace);

        if (manifest.IncompleteArtifacts || manifest.IdentityRejected || manifest.TeardownOnly
            || !manifest.HasVerifiedPrimaryFault)
        {
            return new HypothesisSetDto(
                false,
                crashId,
                project,
                [],
                DateTimeOffset.UtcNow,
                Error: manifest.BlockReason ?? "Primary fault unavailable — hypothesis generation blocked",
                SchemaVersion: CurrentSchemaVersion,
                Manifest: manifest);
        }

        var hypotheses = new List<HypothesisDto>();
        AddPatternDepthHypotheses(hypotheses, crashId, corruptionChain, debugger, sidecar, evidenceRefs, baseline);
        AddLineageHypotheses(hypotheses, crashId, corruptionChain, evolution, sidecar, evidenceRefs, baseline);
        AddDebuggerHypotheses(hypotheses, crashId, debugger, corruptionChain, sidecar, evidenceRefs, baseline);
        AddBackwardTraceHypotheses(hypotheses, crashId, backwardTrace, corruptionChain, sidecar, evidenceRefs, baseline);
        AddOracleHypotheses(hypotheses, crashId, oracleScore, sidecar, corruptionChain, evidenceRefs, baseline);
        AddStagnationHypotheses(hypotheses, crashId, evolution, sidecar, corruptionChain, evidenceRefs, baseline);
        AddTriggerSensitivityHypothesis(hypotheses, crashId, corruptionChain, sidecar, evidenceRefs, baseline);

        var ranked = hypotheses
            .Select(NormalizeHypothesis)
            .OrderByDescending(h => h.ConfidencePercent)
            .ThenBy(h => h.TypeId ?? h.Id, StringComparer.Ordinal)
            .ToList();

        return new HypothesisSetDto(
            ranked.Count > 0,
            crashId,
            project,
            ranked,
            DateTimeOffset.UtcNow,
            SchemaVersion: CurrentSchemaVersion,
            Manifest: manifest);
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
        CrashBackwardTraceDto? backwardTrace = null,
        ArtifactValidationResult? artifactValidation = null,
        IReadOnlyList<EvidenceFact>? evidenceFacts = null)
    {
        artifactValidation ??= CrashArtifactIdentityService.ResolveForCrash(crashesDir, crashId, sidecar, debugger);
        evidenceFacts ??= EvidenceFactBuilder.TryReadForCrash(crashesDir, crashId)?.Facts;
        var set = Build(crashId, project, sidecar, triage, debugger, corruptionChain, evolution, oracleScore,
            backwardTrace, artifactValidation, evidenceFacts);
        Write(crashesDir, set);
        return set;
    }

    public static string Write(string crashesDir, HypothesisSetDto set)
    {
        Directory.CreateDirectory(LedgerDir(crashesDir));
        var path = PathFor(crashesDir, set.CrashId);
        var toWrite = set.SchemaVersion < CurrentSchemaVersion
            ? MigrateIfNeeded(set) with { SchemaVersion = CurrentSchemaVersion }
            : set.SchemaVersion == 0
                ? set with { SchemaVersion = CurrentSchemaVersion }
                : set;
        if (toWrite.SchemaVersion != CurrentSchemaVersion)
            toWrite = toWrite with { SchemaVersion = CurrentSchemaVersion };
        ResearchSidecarIO.WriteAtomic(path, JsonSerializer.Serialize(toWrite, JsonOptions));
        SyncProjectLedger(toWrite.Project, crashesDir, TryLoadQueue(toWrite.Project)?.Iteration ?? 0);
        return path;
    }

    public static HypothesisDto? TopPending(HypothesisSetDto? set) =>
        set?.Hypotheses.FirstOrDefault(h =>
            h.Status is HypothesisStatus.Pending or HypothesisStatus.Proposed
                or HypothesisStatus.Running or HypothesisStatus.Testing
                or HypothesisStatus.Supported or HypothesisStatus.Weakened
                or HypothesisStatus.Inconclusive or HypothesisStatus.Partial);

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
        if (snap?.TopHypothesis is { } queued && queued.IsOpen
            && (best is null || queued.ConfidencePercent > best.ConfidencePercent))
            return queued;

        return best;
    }

    public static bool MarkRunning(string crashesDir, Guid crashId, string hypothesisId)
    {
        var set = TryReadForCrash(crashesDir, crashId);
        if (set is null) return false;
        var hyp = FindHypothesis(set, hypothesisId);
        if (hyp is null || hyp.Status is not (HypothesisStatus.Pending or HypothesisStatus.Proposed
                or HypothesisStatus.Supported or HypothesisStatus.Weakened or HypothesisStatus.Inconclusive
                or HypothesisStatus.Partial))
            return false;
        var updated = hyp with { Status = HypothesisStatus.Testing };
        Write(crashesDir, set with
        {
            Hypotheses = set.Hypotheses.Select(h => h.Id.Equals(updated.Id, StringComparison.OrdinalIgnoreCase) ? updated : h).ToList(),
            SchemaVersion = CurrentSchemaVersion,
        });
        return true;
    }

    public static void EnqueueFromHypothesis(
        string project,
        HypothesisDto hypothesis,
        int iteration,
        string? repoRoot = null)
    {
        if (!hypothesis.IsOpen && hypothesis.Status is not (HypothesisStatus.Pending or HypothesisStatus.Proposed
                or HypothesisStatus.Running or HypothesisStatus.Testing))
            return;
        if (hypothesis.ConfidencePercent < MinExperimentConfidence)
            return;
        if (hypothesis.CrashId is not Guid crashId)
            return;
        if (hypothesis.Status is HypothesisStatus.Blocked or HypothesisStatus.LegacyUnverified
            or HypothesisStatus.Invalidated)
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
            DateTimeOffset.UtcNow,
            hypothesis.TypeId));

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
            entry.RemainingBudget,
            entry.TypeId);
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
            HypothesisExperimentKind.CounterfactualSafeAdjacent => ApplySweepOffset(basePayload, experiment, sweepIndex),
            _ => basePayload.ToArray(),
        };
    }

    /// <summary>Record experiment outcome. Exit-code-only crashes do not Confirm typed hypotheses.</summary>
    public static void RecordOutcome(
        string project,
        HypothesisExperimentPlan plan,
        int iteration,
        bool crashed,
        string? crashClass,
        string? faultDetail,
        string? repoRoot = null,
        FaultIdentitySnapshot? observedFault = null)
    {
        var repo = repoRoot ?? CrashCatalog.FindRepoRoot();
        if (repo is null)
            return;

        var crashesDir = Path.Combine(repo, "data", "crashes", project);
        var set = TryReadForCrash(crashesDir, plan.CrashId);
        if (set is null)
            return;

        var hyp = FindHypothesis(set, plan.HypothesisId);
        if (hyp is null)
            return;

        if (hyp.Status is HypothesisStatus.Blocked or HypothesisStatus.LegacyUnverified or HypothesisStatus.Invalidated)
            return;

        if (!HypothesisExperimentRegistry.IsAllowed(hyp, plan.Experiment.Kind))
        {
            var blocked = hyp with
            {
                Result = new HypothesisResultDto(
                    HypothesisStatus.Inconclusive,
                    hyp.ConfidencePercent,
                    $"Experiment {plan.Experiment.Kind} not registered for {hyp.Kind}/{hyp.HypothesisTypeId} — support unchanged",
                    iteration, DateTimeOffset.UtcNow, hyp.ConfidencePercent,
                    SupportReasons: ["registry:rejected"]),
            };
            Write(crashesDir, ReplaceHypothesis(set, blocked));
            AdvanceOrRemoveQueue(project, plan, iteration, remainingAfter: plan.RemainingBudget - 1,
                status: HypothesisStatus.Inconclusive, updated: blocked, repoRoot);
            return;
        }

        observedFault ??= InferObservedFault(crashed, crashClass, faultDetail, hyp.BaselineFault);
        var scoreBefore = hyp.ConfidencePercent;
        var remainingAfter = plan.RemainingBudget - 1;
        var evaluation = EvaluateOutcome(hyp, crashed, observedFault, remainingAfter, plan.Experiment.Kind);

        var updated = hyp with
        {
            Status = evaluation.Status,
            ConfidencePercent = evaluation.SupportScoreAfter,
            SupportGrade = GradeFor(evaluation.Status, evaluation.SupportScoreAfter),
            SupportReasons = evaluation.SupportReasons,
            Result = HypothesisResultDto.FromExperimentResult(evaluation with { Iteration = iteration }),
        };

        Write(crashesDir, ReplaceHypothesis(set, updated));
        InfluenceEngine.RefreshFromHypotheses(crashesDir, plan.CrashId, ReplaceHypothesis(set, updated));
        AdvanceOrRemoveQueue(project, plan, iteration, remainingAfter, evaluation.Status, updated, repoRoot);
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
        $"Hypothesis [support={hypothesis.SupportScore} {hypothesis.SupportGrade}] {hypothesis.HypothesisTypeId}@{hypothesis.Id}: {hypothesis.Statement} " +
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
        sb.AppendLine($"[{DateTimeOffset.UtcNow:u}] iter={iteration} · **hypothesis** `{hypothesis.HypothesisTypeId}` id=`{hypothesis.Id}` (support={hypothesis.SupportScore})");
        sb.AppendLine($"  {hypothesis.Statement}");
        sb.AppendLine($"  experiment: {hypothesis.Experiment.Kind} — {hypothesis.Experiment.Description}");
        sb.AppendLine($"  expect: {hypothesis.ExpectedObservation}");
        if (hypothesis.ExpectedPredicate is { } pred)
            sb.AppendLine($"  predicate: {pred.Kind}");
        if (!string.IsNullOrWhiteSpace(experimentHint))
            sb.AppendLine($"  hunt: {experimentHint}");
        sb.AppendLine("  Phase D: live TTD rewind remains external (stub only).");
        sb.AppendLine();
        File.AppendAllText(path, sb.ToString());
        return path;
    }

    /// <summary>
    /// Apply counterfactual safe-adjacent evidence — only to TriggerSensitivity hyps via registry.
    /// </summary>
    public static HypothesisSetDto ApplyCounterfactualSupport(
        HypothesisSetDto set,
        CounterfactualReportDto report,
        List<string> updatedIds)
    {
        if (set.Hypotheses.Count == 0)
            return set;

        var candidates = set.Hypotheses
            .Where(HypothesisExperimentRegistry.AllowsCounterfactualSafeAdjacent)
            .Where(h => h.IsOpen || h.Status is HypothesisStatus.Pending or HypothesisStatus.Proposed)
            .OrderByDescending(h => h.ConfidencePercent)
            .ToList();

        if (candidates.Count == 0)
            return set; // no leakage onto MutatorCorrelation / oracle hyps

        var target = candidates[0];
        var before = target.ConfidencePercent;
        HypothesisStatus status;
        int after;
        string observation;
        var reasons = new List<string>();
        var deltas = new List<string>();

        if (report.SmallestSafeChange is not null)
        {
            status = HypothesisStatus.Supported;
            after = Math.Min(88, before + SupportDelta.SafeAdjacentSupport);
            observation =
                $"Counterfactual live: safe-adjacent via {report.SmallestSafeChange.Description} " +
                $"(Δ{report.SmallestSafeChange.ByteDelta}) — supports TriggerSensitivity only";
            reasons.Add("predicate:TriggerSensitiveRegion");
            deltas.Add($"+{SupportDelta.SafeAdjacentSupport} safe-adjacent region");
        }
        else if (report.StillCorruptCount > 0 && report.SafeAdjacentCount == 0)
        {
            status = HypothesisStatus.Inconclusive;
            after = before;
            observation =
                $"Counterfactual live: {report.StillCorruptCount} still-corrupt — no safe-adjacent boundary";
            reasons.Add("counterfactual:still-corrupt");
        }
        else
        {
            status = HypothesisStatus.Inconclusive;
            after = before;
            observation = "Counterfactual live: inconclusive boundary map";
            reasons.Add("counterfactual:inconclusive");
        }

        var updated = target with
        {
            Status = status,
            ConfidencePercent = after,
            SupportGrade = GradeFor(status, after),
            SupportReasons = reasons,
            Kind = HypothesisKind.TriggerSensitivity,
            ExpectedPredicate = target.ExpectedPredicate ?? new ExpectedPredicate(
                HypothesisPredicateKind.TriggerSensitiveRegion,
                HumanSummary: "Safe-adjacent flip supports trigger-sensitive region"),
            Result = new HypothesisResultDto(
                status, after, observation, null, DateTimeOffset.UtcNow, before,
                SupportReasons: reasons, SupportDeltas: deltas),
        };
        updatedIds.Add(updated.Id);

        return ReplaceHypothesis(set, updated) with { At = DateTimeOffset.UtcNow, SchemaVersion = CurrentSchemaVersion };
    }

    /// <summary>Compare baseline vs observed fault identity.</summary>
    public static FaultComparison CompareFaults(FaultIdentitySnapshot? baseline, FaultIdentitySnapshot? observed)
    {
        if (baseline is null || observed is null)
        {
            return new FaultComparison(false, false, false, false, false, false, false,
                "Missing baseline or observed fault identity");
        }

        var exit = baseline.ExitCode is int be && observed.ExitCode is int oe && be == oe
                   || (!string.IsNullOrWhiteSpace(baseline.CrashClass)
                       && string.Equals(baseline.CrashClass, observed.CrashClass, StringComparison.OrdinalIgnoreCase));
        var module = !string.IsNullOrWhiteSpace(baseline.FaultModule)
                     && string.Equals(baseline.FaultModule, observed.FaultModule, StringComparison.OrdinalIgnoreCase);
        var offset = !string.IsNullOrWhiteSpace(baseline.FaultOffset)
                     && string.Equals(baseline.FaultOffset, observed.FaultOffset, StringComparison.OrdinalIgnoreCase);
        var access = !string.IsNullOrWhiteSpace(baseline.AccessKind)
                     && string.Equals(baseline.AccessKind, observed.AccessKind, StringComparison.OrdinalIgnoreCase);
        var stack = !string.IsNullOrWhiteSpace(baseline.StackFingerprint)
                    && string.Equals(baseline.StackFingerprint, observed.StackFingerprint, StringComparison.OrdinalIgnoreCase);
        var family = !string.IsNullOrWhiteSpace(baseline.FamilyId)
                     && string.Equals(baseline.FamilyId, observed.FamilyId, StringComparison.OrdinalIgnoreCase);

        // Primary fault match requires more than generic AV exit.
        var primary = baseline.HasVerifiedPrimaryFault && observed.HasVerifiedPrimaryFault
                      && !observed.IsTeardownOnly
                      && (module || offset || stack)
                      && (access || family || module);

        var parts = new List<string>();
        if (exit) parts.Add("exit");
        if (module) parts.Add("module");
        if (offset) parts.Add("offset");
        if (access) parts.Add("access");
        if (stack) parts.Add("stack");
        if (family) parts.Add("family");
        var summary = primary
            ? $"Primary fault match ({string.Join(",", parts)})"
            : exit && !primary
                ? $"Abnormal exit only ({observed.ExitCode?.ToString() ?? observed.CrashClass ?? "?"}) — not same primary fault"
                : parts.Count > 0
                    ? $"Partial match ({string.Join(",", parts)})"
                    : "No fault identity match";

        return new FaultComparison(exit, module, offset, access, stack, family, primary, summary);
    }

    public static HypothesisSupportGrade GradeFor(HypothesisStatus status, int supportScore) =>
        status switch
        {
            HypothesisStatus.Confirmed => HypothesisSupportGrade.Confirmed,
            HypothesisStatus.Refuted or HypothesisStatus.Blocked or HypothesisStatus.Invalidated
                or HypothesisStatus.LegacyUnverified => HypothesisSupportGrade.Unsupported,
            _ when supportScore >= 80 => HypothesisSupportGrade.Strong,
            _ when supportScore >= 60 => HypothesisSupportGrade.Moderate,
            _ when supportScore >= 40 => HypothesisSupportGrade.Weak,
            _ => HypothesisSupportGrade.Unsupported,
        };

    /// <summary>Propagate invalidated evidence refs onto open hypotheses.</summary>
    public static HypothesisSetDto PropagateInvalidatedEvidence(
        HypothesisSetDto set,
        IReadOnlySet<string> invalidatedFactIds)
    {
        if (invalidatedFactIds.Count == 0) return set;
        var list = set.Hypotheses.Select(h =>
        {
            if (h.EvidenceRefs is not { Count: > 0 }) return h;
            var refs = h.EvidenceRefs.Select(r =>
                invalidatedFactIds.Contains(r.FactId) ? r with { Invalidated = true } : r).ToList();
            if (!refs.Any(r => r.Invalidated)) return h with { EvidenceRefs = refs };
            return h with
            {
                EvidenceRefs = refs,
                Status = HypothesisStatus.Invalidated,
                SupportGrade = HypothesisSupportGrade.Unsupported,
                SupportReasons = ["evidence:invalidated"],
            };
        }).ToList();
        return set with { Hypotheses = list, At = DateTimeOffset.UtcNow };
    }

    // ── Build helpers ────────────────────────────────────────────────────────

    private static HypothesisDto Create(
        string typeId,
        HypothesisKind kind,
        Guid crashId,
        string statement,
        int supportScore,
        HypothesisExperimentDto experiment,
        ExpectedPredicate predicate,
        IReadOnlyList<HypothesisEvidenceRef> evidenceRefs,
        FaultIdentitySnapshot? baseline)
    {
        var expectedText = predicate.HumanSummary
                           ?? DeriveExpectedText(predicate);
        return NormalizeHypothesis(new HypothesisDto(
            Guid.NewGuid().ToString("N"),
            crashId,
            statement,
            Math.Clamp(supportScore, 1, 92),
            experiment,
            expectedText,
            HypothesisStatus.Proposed,
            Evidence: evidenceRefs.Select(r => r.FactId).ToList(),
            TypeId: typeId,
            Kind: kind,
            ExpectedPredicate: predicate,
            EvidenceRefs: evidenceRefs,
            SupportGrade: GradeFor(HypothesisStatus.Proposed, supportScore),
            SupportReasons: [$"seed:{kind}"],
            BaselineFault: baseline));
    }

    private static string DeriveExpectedText(ExpectedPredicate p) => p.Kind switch
    {
        HypothesisPredicateKind.SamePrimaryFault =>
            "Same primary fault identity (module/offset/access/family) — exit alone is insufficient",
        HypothesisPredicateKind.TriggerSensitiveRegion =>
            "Safe-adjacent or offset sweep shows trigger-sensitive region",
        HypothesisPredicateKind.MutatorCorrelationCampaign =>
            $"Campaign mutator correlation (exec≥{p.MinExecutions ?? MutatorCorrelationMinExecutions}, crashes≥{p.MinCrashes ?? MutatorCorrelationMinCrashes})",
        HypothesisPredicateKind.FamilyProgressionAdvanced =>
            p.MinMomentum is int m
                ? $"Family progression advances (momentum>{m}) with matching primary fault"
                : "Family progression step advances with matching primary fault",
        HypothesisPredicateKind.CapabilityControl =>
            "Capability control claim reproduced with same primary fault",
        _ => "Observation matches predicate",
    };

    private static void AddPatternDepthHypotheses(
        List<HypothesisDto> list,
        Guid crashId,
        CrashCorruptionChainDto? chain,
        DebuggerObservation? debugger,
        CrashSidecarDto? sidecar,
        IReadOnlyList<HypothesisEvidenceRef> evidence,
        FaultIdentitySnapshot? baseline)
    {
        if (chain?.PatternDepthBytes is not int offset)
            return;

        var access = debugger?.Access is DebuggerAccessKind.Write or DebuggerAccessKind.Execute
            ? debugger.Access.ToString()
            : "fault";
        var mutator = chain.SuspectedMutator ?? sidecar?.Mutator ?? "havoc";
        var confidence = ScoreBase(chain.Confidence) + SupportDelta.PatternDepthBonus;
        if (debugger?.SuspectedInputInfluence.Equals("HIGH", StringComparison.OrdinalIgnoreCase) == true)
            confidence += SupportDelta.HighInfluenceBonus;

        var sweepRange = Math.Min(8, Math.Max(2, offset / 8 + 2));
        list.Add(Create(
            $"hyp-offset-{offset:X}",
            HypothesisKind.TriggerSensitivity,
            crashId,
            $"Input byte at offset {offset} (0x{offset:X}) influences {access} fault — {chain.SuspectedField ?? "payload field"}",
            confidence,
            new HypothesisExperimentDto(
                HypothesisExperimentKind.SweepOffset,
                $"Sweep ±{sweepRange} bytes around offset {offset}",
                "bitflip",
                offset,
                sweepRange,
                chain.MutatorLineage,
                sidecar?.Command),
            new ExpectedPredicate(
                HypothesisPredicateKind.TriggerSensitiveRegion,
                baseline,
                RegionLabel: $"offset:{offset}",
                HumanSummary: "Same crash class with fault address tracking sweep; trigger-sensitive if safe-adjacent clears"),
            evidence,
            baseline));

        if (offset >= 4)
        {
            list.Add(Create(
                $"hyp-boundary-{offset:X}",
                HypothesisKind.InputRegionInfluence,
                crashId,
                $"Boundary values at offset {offset} drive {access} — probe interesting integers/lengths",
                confidence - 8,
                new HypothesisExperimentDto(
                    HypothesisExperimentKind.BoundaryProbe,
                    $"Probe 0, MAX-1, MAX at offset {offset}",
                    "interesting",
                    offset,
                    Command: sidecar?.Command),
                new ExpectedPredicate(
                    HypothesisPredicateKind.SamePrimaryFault,
                    baseline,
                    RegionLabel: $"offset:{offset}",
                    HumanSummary: "Crash reproduces with boundary values at offset and same primary fault"),
                evidence,
                baseline));
        }
    }

    private static void AddLineageHypotheses(
        List<HypothesisDto> list,
        Guid crashId,
        CrashCorruptionChainDto? chain,
        ScreamEvolutionDto? evolution,
        CrashSidecarDto? sidecar,
        IReadOnlyList<HypothesisEvidenceRef> evidence,
        FaultIdentitySnapshot? baseline)
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

        list.Add(Create(
            $"hyp-lineage-{mutator}",
            HypothesisKind.MutatorCorrelation,
            crashId,
            $"Mutator '{mutator}' on lineage {string.Join("→", lineage)} correlates with scream family {evolution?.FamilyId ?? chain?.Summary ?? "cluster"} (campaign-level; needs sample size)",
            confidence,
            new HypothesisExperimentDto(
                HypothesisExperimentKind.ReplayLineage,
                $"Replay chain {string.Join("→", lineage)} from seed",
                mutator,
                MutatorChain: lineage,
                Command: sidecar?.Command),
            new ExpectedPredicate(
                HypothesisPredicateKind.MutatorCorrelationCampaign,
                baseline,
                MinExecutions: MutatorCorrelationMinExecutions,
                MinCrashes: MutatorCorrelationMinCrashes,
                Mutator: mutator,
                FamilyId: evolution?.FamilyId,
                HumanSummary: $"Campaign correlation for '{mutator}' (exec≥{MutatorCorrelationMinExecutions}, crashes≥{MutatorCorrelationMinCrashes}); teardown excluded"),
            evidence,
            baseline));

        list.Add(Create(
            $"hyp-hold-{mutator}",
            HypothesisKind.ReplaySamePrimaryFault,
            crashId,
            $"Holding mutator '{mutator}' on crash input preserves primary fault — minimize elsewhere",
            confidence - 5,
            new HypothesisExperimentDto(
                HypothesisExperimentKind.HoldMutator,
                $"Hold {mutator} on crash input, havoc elsewhere",
                mutator,
                MutatorChain: lineage,
                Command: sidecar?.Command),
            new ExpectedPredicate(
                HypothesisPredicateKind.SamePrimaryFault,
                baseline,
                Mutator: mutator,
                HumanSummary: "Crash persists with held mutator and same primary fault identity"),
            evidence,
            baseline));
    }

    private static void AddDebuggerHypotheses(
        List<HypothesisDto> list,
        Guid crashId,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? chain,
        CrashSidecarDto? sidecar,
        IReadOnlyList<HypothesisEvidenceRef> evidence,
        FaultIdentitySnapshot? baseline)
    {
        if (debugger is not { Ok: true })
            return;

        if (debugger.FaultAddressClass == DebuggerAddressClass.AsciiPattern
            && chain?.PatternDepthBytes is int off)
        {
            list.Add(Create(
                $"hyp-ascii-{off:X}",
                HypothesisKind.DestinationControl,
                crashId,
                $"Fault address matches ASCII/pattern at input offset {off} — controlled pointer from payload",
                ScoreBase(chain.Confidence) + 15,
                new HypothesisExperimentDto(
                    HypothesisExperimentKind.MinimizeHold,
                    $"Preserve bytes [{off},{off + 4}) while shrinking tail",
                    chain.SuspectedMutator ?? "expand",
                    off,
                    SweepRange: 4,
                    Command: sidecar?.Command),
                new ExpectedPredicate(
                    HypothesisPredicateKind.CapabilityControl,
                    baseline,
                    RegionLabel: $"offset:{off}",
                    HumanSummary: "Minimized input still crashes with same fault address class / primary fault"),
                evidence,
                baseline));
        }

        if (debugger.Access == DebuggerAccessKind.Write
            && evolutionProgressionWarming(debugger, chain)
            && debugger.FaultAddressClass is not (DebuggerAddressClass.NullPage
                or DebuggerAddressClass.NearNull
                or DebuggerAddressClass.SmallOffset)
            && !InputAttributionEngine.IsExcludedFromRawInputAttribution(debugger.FaultAddress))
        {
            var site = !string.IsNullOrWhiteSpace(debugger.FaultingFunction)
                       && !ScreamInvestigator.IsGarbageSymbol(debugger.FaultingFunction, debugger.FaultingModule)
                ? debugger.FaultingFunction
                : debugger.Rip ?? "fault site";
            list.Add(Create(
                "hyp-write-progression",
                HypothesisKind.FamilyProgression,
                crashId,
                $"Write violation at {site} — breeding may reach controlled write (requires progression evidence, not exit alone)",
                Math.Clamp(55 + debugger.DebuggerScreamBonus / 5, 45, 85),
                new HypothesisExperimentDto(
                    HypothesisExperimentKind.HoldMutator,
                    "Hold expand/cyclic on warming lineage input",
                    chain?.SuspectedMutator ?? "cyclic",
                    MutatorChain: chain?.MutatorLineage,
                    Command: sidecar?.Command),
                new ExpectedPredicate(
                    HypothesisPredicateKind.FamilyProgressionAdvanced,
                    baseline,
                    FamilyId: baseline?.FamilyId,
                    HumanSummary: "Same family with equal or higher progression step AND matching primary fault"),
                evidence,
                baseline));
        }
    }

    private static void AddOracleHypotheses(
        List<HypothesisDto> list,
        Guid crashId,
        OracleScore? oracleScore,
        CrashSidecarDto? sidecar,
        CrashCorruptionChainDto? chain,
        IReadOnlyList<HypothesisEvidenceRef> evidence,
        FaultIdentitySnapshot? baseline)
    {
        if (oracleScore is not { Total: >= 35 })
            return;

        var term = oracleScore.Terms.FirstOrDefault(t => t.Points >= 10);
        var label = term?.Label ?? "oracle signal";
        var mutator = chain?.SuspectedMutator ?? sidecar?.Mutator ?? "?";
        list.Add(Create(
            "hyp-oracle-correlate",
            HypothesisKind.MutatorCorrelation,
            crashId,
            $"Oracle '{label}' correlates with mutator '{mutator}' on command '{sidecar?.Command ?? "default"}' (campaign baseline required)",
            Math.Clamp(40 + oracleScore.Total / 4, 40, 78),
            new HypothesisExperimentDto(
                HypothesisExperimentKind.ReplayLineage,
                "Replay crash input with dictionary/interesting pressure",
                "interesting",
                MutatorChain: chain?.MutatorLineage ?? sidecar?.MutatorChain,
                Command: sidecar?.Command),
            new ExpectedPredicate(
                HypothesisPredicateKind.MutatorCorrelationCampaign,
                baseline,
                MinExecutions: MutatorCorrelationMinExecutions,
                MinCrashes: MutatorCorrelationMinCrashes,
                Mutator: mutator,
                HumanSummary: "Campaign-level oracle↔mutator correlation; SweepOffset/safe-adjacent do not support this claim"),
            evidence,
            baseline));
    }

    private static void AddStagnationHypotheses(
        List<HypothesisDto> list,
        Guid crashId,
        ScreamEvolutionDto? evolution,
        CrashSidecarDto? sidecar,
        CrashCorruptionChainDto? chain,
        IReadOnlyList<HypothesisEvidenceRef> evidence,
        FaultIdentitySnapshot? baseline)
    {
        if (evolution is not { Ok: true, Generation: >= 2, MomentumScore: >= 35 and < 50 })
            return;

        list.Add(Create(
            $"hyp-stall-{evolution.FamilyId}",
            HypothesisKind.FamilyProgression,
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
                chain?.PatternDepthBytes is int ? 6 : null,
                chain?.MutatorLineage,
                sidecar?.Command),
            new ExpectedPredicate(
                HypothesisPredicateKind.FamilyProgressionAdvanced,
                baseline,
                MinMomentum: evolution.MomentumScore,
                FamilyId: evolution.FamilyId,
                HumanSummary: $"Momentum rises above {evolution.MomentumScore} or progression advances with same primary fault"),
            evidence,
            baseline));
    }

    private static void AddTriggerSensitivityHypothesis(
        List<HypothesisDto> list,
        Guid crashId,
        CrashCorruptionChainDto? chain,
        CrashSidecarDto? sidecar,
        IReadOnlyList<HypothesisEvidenceRef> evidence,
        FaultIdentitySnapshot? baseline)
    {
        if (chain?.PatternDepthBytes is not int offset)
            return;
        // Dedicated TriggerSensitivity row so counterfactual updates have a typed target.
        if (list.Any(h => h.Kind == HypothesisKind.TriggerSensitivity))
            return;

        list.Add(Create(
            $"hyp-cf-trigger-{offset:X}",
            HypothesisKind.TriggerSensitivity,
            crashId,
            $"Region around offset {offset} is trigger-sensitive (safe-adjacent / bit-flip boundary)",
            55,
            new HypothesisExperimentDto(
                HypothesisExperimentKind.CounterfactualSafeAdjacent,
                $"Counterfactual probes around offset {offset}",
                "bitflip",
                offset,
                4,
                Command: sidecar?.Command),
            new ExpectedPredicate(
                HypothesisPredicateKind.TriggerSensitiveRegion,
                baseline,
                RegionLabel: $"offset:{offset}"),
            evidence,
            baseline));
    }

    private static void AddBackwardTraceHypotheses(
        List<HypothesisDto> list,
        Guid crashId,
        CrashBackwardTraceDto? trace,
        CrashCorruptionChainDto? chain,
        CrashSidecarDto? sidecar,
        IReadOnlyList<HypothesisEvidenceRef> evidence,
        FaultIdentitySnapshot? baseline)
    {
        if (trace is not { Ok: true })
            return;

        if (trace.FaultRegister is not null && trace.PrimaryPayloadOffset is not null)
        {
            list.Add(Create(
                $"hyp-btrace-reg-{trace.FaultRegister.ToLowerInvariant()}",
                HypothesisKind.WrittenValueControl,
                crashId,
                $"Backward trace: {trace.FaultRegister} from payload{trace.PrimaryPayloadOffset} drives fault — mutation '{trace.SuspectedMutator ?? chain?.SuspectedMutator ?? "?"}'",
                ScoreBase(trace.Confidence) + 10,
                new HypothesisExperimentDto(
                    HypothesisExperimentKind.ReplayLineage,
                    $"Replay lineage preserving payload{trace.PrimaryPayloadOffset}",
                    trace.SuspectedMutator ?? chain?.SuspectedMutator ?? "havoc",
                    MutatorChain: chain?.MutatorLineage,
                    Command: sidecar?.Command),
                new ExpectedPredicate(
                    HypothesisPredicateKind.CapabilityControl,
                    baseline,
                    RegionLabel: $"payload{trace.PrimaryPayloadOffset}",
                    HumanSummary: $"Replay reproduces same {trace.FaultRegister} value at fault with same primary fault"),
                evidence,
                baseline));
        }

        if (trace.HeapTimeline is not null)
        {
            list.Add(Create(
                "hyp-btrace-heap",
                HypothesisKind.RootCause,
                crashId,
                $"Heap timeline ({trace.HeapTimeline}) — UAF/corruption hypothesis from dump probes",
                ScoreBase(trace.Confidence) + 5,
                new HypothesisExperimentDto(
                    HypothesisExperimentKind.HoldMutator,
                    "Hold heap-touching mutator; vary alloc pattern elsewhere",
                    trace.SuspectedMutator ?? chain?.SuspectedMutator ?? "havoc",
                    MutatorChain: chain?.MutatorLineage,
                    Command: sidecar?.Command),
                new ExpectedPredicate(
                    HypothesisPredicateKind.SamePrimaryFault,
                    baseline,
                    HumanSummary: "Same heap signal on replay with matching primary fault"),
                evidence,
                baseline));
        }

        if (!string.IsNullOrWhiteSpace(trace.BadPointerSource))
        {
            var story = trace.Story ?? "";
            if (story.Contains("controlled write in !:", StringComparison.OrdinalIgnoreCase)
                || story.Contains("controlled write in !", StringComparison.OrdinalIgnoreCase))
            {
                story = story
                    .Replace("controlled write in !:", "null/invalid destination write", StringComparison.OrdinalIgnoreCase)
                    .Replace("controlled write in !", "null/invalid destination write", StringComparison.OrdinalIgnoreCase);
            }

            list.Add(Create(
                "hyp-btrace-source",
                HypothesisKind.RootCause,
                crashId,
                $"Bad pointer source: {trace.BadPointerSource} — {story}",
                ScoreBase(trace.Confidence),
                new HypothesisExperimentDto(
                    HypothesisExperimentKind.MinimizeHold,
                    "Preserve attributed bytes; shrink unrelated payload",
                    trace.SuspectedMutator ?? chain?.SuspectedMutator ?? "expand",
                    chain?.PatternDepthBytes,
                    Command: sidecar?.Command),
                new ExpectedPredicate(
                    HypothesisPredicateKind.SamePrimaryFault,
                    baseline,
                    HumanSummary: "Minimized crash retains backward trace story and fault register"),
                evidence,
                baseline));
        }
    }

    private static HypothesisArtifactManifest BuildManifest(
        DebuggerObservation? debugger,
        ArtifactValidationResult? validation,
        CrashCorruptionChainDto? chain)
    {
        var rejected = validation?.Status == ArtifactIntegrityStatus.Rejected;
        var teardown = validation?.SecondaryException is SecondaryExceptionKind.Teardown
            or SecondaryExceptionKind.SecondaryException;
        var debuggerOk = debugger is { Ok: true };
        var hasPrimary = debuggerOk
            && !teardown
            && !rejected
            && (debugger!.FaultAddress is not null
                || debugger.FaultingModule is not null
                || debugger.Access != DebuggerAccessKind.Unknown);
        // Without validation envelope, require debugger primary signals (exit-only is insufficient).
        if (validation is null)
            hasPrimary = debuggerOk && (debugger!.FaultAddress is not null || debugger.FaultingModule is not null);

        var incomplete = !debuggerOk && chain is not { Ok: true };
        string? block = null;
        if (rejected) block = validation?.Summary ?? "Artifact identity Rejected";
        else if (teardown) block = "Teardown/secondary-only fault — capability hypotheses blocked";
        else if (!hasPrimary) block = "Verified primary fault unavailable (exit-only / missing debugger artifacts)";
        else if (incomplete) block = "Incomplete crash artifacts — hypotheses unavailable";

        var caps = new List<string>();
        if (hasPrimary) caps.Add(nameof(HypothesisArtifactManifest.HasVerifiedPrimaryFault));
        if (debuggerOk) caps.Add("DebuggerArtifacts");
        if (chain is { Ok: true }) caps.Add("CorruptionChain");

        return new HypothesisArtifactManifest(
            HasVerifiedPrimaryFault: hasPrimary,
            DebuggerArtifactsPresent: debuggerOk,
            IdentityRejected: rejected,
            TeardownOnly: teardown,
            IncompleteArtifacts: incomplete && !hasPrimary,
            BlockReason: block,
            AvailableCapabilities: caps);
    }

    private static FaultIdentitySnapshot CaptureBaselineFault(
        CrashSidecarDto? sidecar,
        DebuggerObservation? debugger,
        ScreamEvolutionDto? evolution,
        ArtifactValidationResult? validation,
        HypothesisArtifactManifest manifest)
    {
        var teardown = validation?.SecondaryException is SecondaryExceptionKind.Teardown
            or SecondaryExceptionKind.SecondaryException;
        return new FaultIdentitySnapshot(
            ExitCode: sidecar?.ExitCode,
            CrashClass: sidecar?.ExceptionHint ?? debugger?.ExceptionCode,
            FaultModule: debugger?.FaultingModule,
            FaultOffset: debugger?.FunctionOffset ?? debugger?.FaultAddress ?? debugger?.Rip,
            AccessKind: debugger?.Access.ToString(),
            FaultAddressClass: debugger?.FaultAddressClass.ToString(),
            FamilyId: evolution?.FamilyId,
            StackFingerprint: debugger?.StackHash ?? debugger?.FaultingFunction,
            FaultingFunction: debugger?.FaultingFunction,
            IsTeardownOnly: teardown,
            HasVerifiedPrimaryFault: manifest.HasVerifiedPrimaryFault);
    }

    private static IReadOnlyList<HypothesisEvidenceRef> CollectEvidenceRefs(
        IReadOnlyList<EvidenceFact>? facts,
        CrashSidecarDto? sidecar,
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? chain,
        ScreamEvolutionDto? evolution,
        OracleScore? oracleScore,
        CrashBackwardTraceDto? backwardTrace)
    {
        var refs = new List<HypothesisEvidenceRef>();
        if (facts is { Count: > 0 })
        {
            foreach (var f in facts.Take(24))
            {
                if (string.IsNullOrWhiteSpace(f.Name)) continue;
                refs.Add(new HypothesisEvidenceRef(f.Name, f.SourceArtifact));
            }
            return refs;
        }

        // Graceful fallback: synthesize stable fact ids from available sensors (not free-form display tags).
        if (chain is { Ok: true })
            refs.Add(new HypothesisEvidenceRef($"corruption.confidence:{chain.Confidence}", "corruption_chain"));
        if (backwardTrace is { Ok: true })
            refs.Add(new HypothesisEvidenceRef($"backwardTrace.confidence:{backwardTrace.Confidence}", "backward_trace"));
        if (debugger is { Ok: true })
            refs.Add(new HypothesisEvidenceRef($"debugger.access:{debugger.Access}", "debugger"));
        if (evolution is { Ok: true })
            refs.Add(new HypothesisEvidenceRef($"evolution.family:{evolution.FamilyId}", "evolution"));
        if (sidecar?.MutatorChain?.Count > 0)
            refs.Add(new HypothesisEvidenceRef($"lineage:{string.Join("→", sidecar.MutatorChain)}", "sidecar"));
        if (oracleScore is { Total: > 0 })
            refs.Add(new HypothesisEvidenceRef($"oracle.total:{oracleScore.Total}", "oracle"));
        if (triage?.PatternDepthBytes is int d)
            refs.Add(new HypothesisEvidenceRef($"patternDepth:{d}", "triage"));
        return refs;
    }

    /// <summary>Legacy string-tag collector kept for callers; prefers fact ids when possible.</summary>
    public static List<string> CollectEvidence(
        CrashSidecarDto? sidecar,
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? chain,
        ScreamEvolutionDto? evolution,
        OracleScore? oracleScore,
        CrashBackwardTraceDto? backwardTrace = null) =>
        CollectEvidenceRefs(null, sidecar, triage, debugger, chain, evolution, oracleScore, backwardTrace)
            .Select(r => r.FactId)
            .ToList();

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
            evidence.Add($"influence.confidence:{influence.Confidence}");
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

    // ── Evaluation ───────────────────────────────────────────────────────────

    internal static ExperimentResult EvaluateOutcome(
        HypothesisDto hyp,
        bool crashed,
        FaultIdentitySnapshot observed,
        int remainingBudgetAfter,
        HypothesisExperimentKind experimentKind)
    {
        var score = hyp.ConfidencePercent;
        var reasons = new List<string>();
        var deltas = new List<string>();
        var comparison = CompareFaults(hyp.BaselineFault ?? hyp.ExpectedPredicate?.BaselineFault, observed);
        var predicate = hyp.ExpectedPredicate?.Kind
                        ?? InferPredicate(hyp);

        if (!crashed)
        {
            // Flaky / no-crash: weaken or inconclusive — do not Refute after a short budget
            // unless the claim strictly requires deterministic repro (ReplaySamePrimaryFault with high baseline).
            var requiresRepro = hyp.Kind is HypothesisKind.ReplaySamePrimaryFault
                                && (hyp.BaselineFault?.HasVerifiedPrimaryFault == true);
            if (remainingBudgetAfter <= 0 && requiresRepro)
            {
                score = Math.Max(10, score - SupportDelta.RefutePenalty);
                deltas.Add($"-{SupportDelta.RefutePenalty} no-repro exhausted");
                reasons.Add("no-crash:refute-repro-required");
                return new ExperimentResult(
                    HypothesisStatus.Refuted, score,
                    "No crash after budget — repro-required claim refuted",
                    null, DateTimeOffset.UtcNow, hyp.ConfidencePercent, comparison, observed, reasons, deltas);
            }

            score = Math.Max(15, score - SupportDelta.WeakenPenalty);
            deltas.Add($"-{SupportDelta.WeakenPenalty} no-crash");
            reasons.Add(remainingBudgetAfter <= 0 ? "no-crash:budget-exhausted-weaken" : "no-crash:weaken");
            var status = remainingBudgetAfter <= 0
                ? HypothesisStatus.Weakened
                : HypothesisStatus.Inconclusive;
            return new ExperimentResult(
                status, score,
                remainingBudgetAfter <= 0
                    ? "No crash after budget — claim weakened (flaky/inconclusive; not Refuted)"
                    : "No crash — hypothesis weakened (may need different sweep index)",
                null, DateTimeOffset.UtcNow, hyp.ConfidencePercent, comparison, observed, reasons, deltas);
        }

        // Crashed: exit alone never Confirms.
        if (!observed.HasVerifiedPrimaryFault && comparison.PrimaryFaultMatches == false)
        {
            // Generic AV / exit reproduction.
            if (comparison.ExitMatches || observed.ExitCode is not null || !string.IsNullOrWhiteSpace(observed.CrashClass))
            {
                score = Math.Min(90, score + SupportDelta.AbnormalExitSupport);
                deltas.Add($"+{SupportDelta.AbnormalExitSupport} abnormal-exit");
                reasons.Add("abnormal-exit-reproduced");
                reasons.Add("not-confirmed:exit-alone");
                return new ExperimentResult(
                    HypothesisStatus.Supported, score,
                    $"Abnormal exit reproduced ({observed.ExitCode?.ToString() ?? observed.CrashClass ?? "fault"}) — primary fault not verified; not Confirmed",
                    null, DateTimeOffset.UtcNow, hyp.ConfidencePercent, comparison, observed, reasons, deltas);
            }
        }

        var predicateMet = PredicateMet(predicate, hyp, comparison, observed, experimentKind, reasons);
        if (predicateMet)
        {
            // Family progression must show progression signal, not status alone.
            if (predicate == HypothesisPredicateKind.FamilyProgressionAdvanced
                && !FamilyProgressionEvidence(hyp, observed, reasons))
            {
                score = Math.Min(90, score + SupportDelta.AbnormalExitSupport);
                deltas.Add($"+{SupportDelta.AbnormalExitSupport} crash-without-progression");
                reasons.Add("family-progression:predicate-incomplete");
                return new ExperimentResult(
                    HypothesisStatus.Supported, score,
                    $"Crash observed but family progression predicate not met — {comparison.Summary}",
                    null, DateTimeOffset.UtcNow, hyp.ConfidencePercent, comparison, observed, reasons, deltas);
            }

            // MutatorCorrelation needs campaign samples — crash-level replay alone → Supported not Confirmed.
            if (predicate == HypothesisPredicateKind.MutatorCorrelationCampaign)
            {
                score = Math.Min(85, score + SupportDelta.PartialSupport);
                deltas.Add($"+{SupportDelta.PartialSupport} replay-support");
                reasons.Add("mutator-correlation:needs-campaign-baseline");
                return new ExperimentResult(
                    HypothesisStatus.Supported, score,
                    $"Replay crashed with related fault — MutatorCorrelation stays Supported until campaign sample gates met",
                    null, DateTimeOffset.UtcNow, hyp.ConfidencePercent, comparison, observed, reasons, deltas);
            }

            if (comparison.PrimaryFaultMatches
                || predicate is HypothesisPredicateKind.TriggerSensitiveRegion)
            {
                score = Math.Min(95, score + SupportDelta.ConfirmSupport);
                deltas.Add($"+{SupportDelta.ConfirmSupport} predicate-met");
                reasons.Add($"predicate:{predicate}");
                reasons.Add(comparison.Summary);
                return new ExperimentResult(
                    HypothesisStatus.Confirmed, score,
                    $"Predicate {predicate} satisfied — {comparison.Summary}",
                    null, DateTimeOffset.UtcNow, hyp.ConfidencePercent, comparison, observed, reasons, deltas);
            }

            score = Math.Min(90, score + SupportDelta.PartialSupport);
            deltas.Add($"+{SupportDelta.PartialSupport} partial-predicate");
            reasons.Add($"predicate-partial:{predicate}");
            return new ExperimentResult(
                HypothesisStatus.Supported, score,
                $"Crash supports claim but primary-fault identity incomplete — {comparison.Summary}",
                null, DateTimeOffset.UtcNow, hyp.ConfidencePercent, comparison, observed, reasons, deltas);
        }

        if (remainingBudgetAfter <= 0)
        {
            score = Math.Max(15, score - SupportDelta.WrongSignaturePenalty);
            deltas.Add($"-{SupportDelta.WrongSignaturePenalty} wrong-signature");
            reasons.Add("wrong-signature:budget-exhausted");
            return new ExperimentResult(
                HypothesisStatus.Weakened, score,
                $"Crash with different primary fault — weakened: {comparison.Summary}",
                null, DateTimeOffset.UtcNow, hyp.ConfidencePercent, comparison, observed, reasons, deltas);
        }

        score = Math.Max(20, score - 5);
        deltas.Add("-5 signature-mismatch");
        reasons.Add("wrong-signature");
        return new ExperimentResult(
            HypothesisStatus.Inconclusive, score,
            $"Crash with different signature: {comparison.Summary}",
            null, DateTimeOffset.UtcNow, hyp.ConfidencePercent, comparison, observed, reasons, deltas);
    }

    private static bool PredicateMet(
        HypothesisPredicateKind predicate,
        HypothesisDto hyp,
        FaultComparison comparison,
        FaultIdentitySnapshot observed,
        HypothesisExperimentKind experimentKind,
        List<string> reasons)
    {
        switch (predicate)
        {
            case HypothesisPredicateKind.TriggerSensitiveRegion:
                if (experimentKind is HypothesisExperimentKind.SweepOffset
                    or HypothesisExperimentKind.BoundaryProbe
                    or HypothesisExperimentKind.CounterfactualSafeAdjacent
                    or HypothesisExperimentKind.MinimizeHold)
                {
                    reasons.Add("trigger-region:experiment-kind-ok");
                    return comparison.ExitMatches || comparison.PrimaryFaultMatches || observed.ExitCode is not null;
                }
                return false;

            case HypothesisPredicateKind.SamePrimaryFault:
                return comparison.PrimaryFaultMatches;

            case HypothesisPredicateKind.FamilyProgressionAdvanced:
                return comparison.PrimaryFaultMatches || comparison.FamilyMatches;

            case HypothesisPredicateKind.CapabilityControl:
                return comparison.PrimaryFaultMatches
                       || (comparison.ModuleMatches && comparison.AccessMatches);

            case HypothesisPredicateKind.MutatorCorrelationCampaign:
                // Crash-level replay can support, not confirm — handled by caller.
                return comparison.ExitMatches || comparison.PrimaryFaultMatches;

            case HypothesisPredicateKind.AbnormalExitReproduced:
                return comparison.ExitMatches || observed.ExitCode is not null;

            default:
                return comparison.PrimaryFaultMatches;
        }
    }

    private static bool FamilyProgressionEvidence(
        HypothesisDto hyp,
        FaultIdentitySnapshot observed,
        List<string> reasons)
    {
        var minMomentum = hyp.ExpectedPredicate?.MinMomentum;
        // Without an observed momentum/progression sensor on the experiment result, do not Confirm.
        if (minMomentum is int)
        {
            reasons.Add("family-progression:momentum-not-observed-on-experiment");
            return false;
        }
        if (!string.IsNullOrWhiteSpace(hyp.ExpectedPredicate?.FamilyId)
            && !string.Equals(hyp.ExpectedPredicate!.FamilyId, observed.FamilyId, StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add("family-progression:family-mismatch");
            return false;
        }
        // Require family match at minimum; progression step advancement needs evolution sensor (not exit).
        if (string.IsNullOrWhiteSpace(observed.FamilyId))
        {
            reasons.Add("family-progression:no-family-on-observation");
            return false;
        }
        reasons.Add("family-progression:insufficient-progression-signal");
        return false;
    }

    private static HypothesisPredicateKind InferPredicate(HypothesisDto hyp)
    {
        if (hyp.ExpectedPredicate is not null)
            return hyp.ExpectedPredicate.Kind;
        var kind = hyp.Kind != HypothesisKind.Unknown
            ? hyp.Kind
            : HypothesisExperimentRegistry.InferKind(hyp.HypothesisTypeId, hyp.Experiment.Kind);
        return kind switch
        {
            HypothesisKind.TriggerSensitivity => HypothesisPredicateKind.TriggerSensitiveRegion,
            HypothesisKind.MutatorCorrelation => HypothesisPredicateKind.MutatorCorrelationCampaign,
            HypothesisKind.FamilyProgression => HypothesisPredicateKind.FamilyProgressionAdvanced,
            HypothesisKind.DestinationControl or HypothesisKind.WrittenValueControl
                => HypothesisPredicateKind.CapabilityControl,
            _ => HypothesisPredicateKind.SamePrimaryFault,
        };
    }

    private static FaultIdentitySnapshot InferObservedFault(
        bool crashed,
        string? crashClass,
        string? faultDetail,
        FaultIdentitySnapshot? baseline)
    {
        int? exit = null;
        if (int.TryParse(faultDetail, out var code))
            exit = code;
        else if (int.TryParse(crashClass, out var code2))
            exit = code2;

        // FuzzEngine historically passed ExitCode as faultDetail and Detail as crashClass.
        var hasDebuggerIdentity = baseline is { HasVerifiedPrimaryFault: true }
                                  && (baseline.FaultModule is not null || baseline.FaultOffset is not null);

        // Exit-only observation: do not claim verified primary fault.
        return new FaultIdentitySnapshot(
            ExitCode: exit ?? baseline?.ExitCode,
            CrashClass: crashClass ?? baseline?.CrashClass,
            FaultModule: null,
            FaultOffset: null,
            AccessKind: null,
            FaultAddressClass: null,
            FamilyId: null,
            StackFingerprint: null,
            FaultingFunction: null,
            IsTeardownOnly: false,
            HasVerifiedPrimaryFault: false);
    }

    // ── Migration / identity ─────────────────────────────────────────────────

    internal static HypothesisSetDto MigrateIfNeeded(HypothesisSetDto set)
    {
        if (set.SchemaVersion >= CurrentSchemaVersion
            && set.Hypotheses.All(h => LooksLikeInstanceId(h.Id) && !string.IsNullOrWhiteSpace(h.TypeId)))
            return set;

        var migrated = new List<HypothesisDto>();
        foreach (var h in set.Hypotheses)
        {
            var typeId = !string.IsNullOrWhiteSpace(h.TypeId)
                ? h.TypeId!
                : LooksLikeInstanceId(h.Id) ? h.HypothesisTypeId : h.Id;
            var instanceId = LooksLikeInstanceId(h.Id) ? h.Id : Guid.NewGuid().ToString("N");
            var kind = h.Kind != HypothesisKind.Unknown
                ? h.Kind
                : HypothesisExperimentRegistry.InferKind(typeId, h.Experiment.Kind);

            var status = h.Status;
            var legacy = h.LegacyUnverified;
            if (set.SchemaVersion < CurrentSchemaVersion
                && status is HypothesisStatus.Confirmed)
            {
                status = HypothesisStatus.LegacyUnverified;
                legacy = true;
            }

            var evidenceRefs = h.EvidenceRefs
                               ?? (h.Evidence?.Select(e => new HypothesisEvidenceRef(e)).ToList());

            migrated.Add(NormalizeHypothesis(h with
            {
                Id = instanceId,
                TypeId = typeId,
                Kind = kind,
                Status = status,
                LegacyUnverified = legacy,
                EvidenceRefs = evidenceRefs,
                SupportGrade = GradeFor(status, h.ConfidencePercent),
                ExpectedPredicate = h.ExpectedPredicate ?? new ExpectedPredicate(InferPredicate(h with { TypeId = typeId, Kind = kind })),
            }));
        }

        return set with
        {
            Hypotheses = migrated,
            SchemaVersion = CurrentSchemaVersion,
            At = set.At,
        };
    }

    private static bool LooksLikeInstanceId(string id) =>
        Guid.TryParseExact(id, "N", out _) || Guid.TryParse(id, out _);

    private static HypothesisDto NormalizeHypothesis(HypothesisDto h)
    {
        var kind = h.Kind != HypothesisKind.Unknown
            ? h.Kind
            : HypothesisExperimentRegistry.InferKind(h.HypothesisTypeId, h.Experiment.Kind);
        var status = h.Status switch
        {
            HypothesisStatus.Pending => HypothesisStatus.Proposed,
            HypothesisStatus.Running => HypothesisStatus.Testing,
            _ => h.Status,
        };
        return h with
        {
            Kind = kind,
            Status = status,
            TypeId = h.TypeId ?? (LooksLikeInstanceId(h.Id) ? null : h.Id),
            SupportGrade = h.SupportGrade == HypothesisSupportGrade.Unsupported && h.ConfidencePercent > 0
                ? GradeFor(status, h.ConfidencePercent)
                : h.SupportGrade == HypothesisSupportGrade.Unsupported
                    ? GradeFor(status, h.ConfidencePercent)
                    : GradeFor(status, h.ConfidencePercent),
        };
    }

    private static HypothesisDto? FindHypothesis(HypothesisSetDto set, string hypothesisId) =>
        set.Hypotheses.FirstOrDefault(h =>
            h.Id.Equals(hypothesisId, StringComparison.OrdinalIgnoreCase)
            || (h.TypeId?.Equals(hypothesisId, StringComparison.OrdinalIgnoreCase) ?? false));

    private static HypothesisSetDto ReplaceHypothesis(HypothesisSetDto set, HypothesisDto updated) =>
        set with
        {
            Hypotheses = set.Hypotheses
                .Select(h => h.Id.Equals(updated.Id, StringComparison.OrdinalIgnoreCase) ? updated : h)
                .ToList(),
            SchemaVersion = CurrentSchemaVersion,
        };

    private static void AdvanceOrRemoveQueue(
        string project,
        HypothesisExperimentPlan plan,
        int iteration,
        int remainingAfter,
        HypothesisStatus status,
        HypothesisDto updated,
        string? repoRoot)
    {
        var snap = TryLoadQueue(project, repoRoot);
        if (snap?.Queue.Count is not > 0)
            return;

        var entry = snap.Queue.FirstOrDefault(q =>
            q.HypothesisId.Equals(plan.HypothesisId, StringComparison.OrdinalIgnoreCase));
        if (entry is null)
            return;

        if (remainingAfter <= 0 || status is HypothesisStatus.Confirmed or HypothesisStatus.Refuted
            or HypothesisStatus.Blocked or HypothesisStatus.Invalidated)
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
                RemainingBudget = remainingAfter,
                SweepIndex = entry.SweepIndex + 1,
                ConfidencePercent = updated.ConfidencePercent,
            };
            PersistQueue(project, iteration, queue, updated, repoRoot);
        }
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
}

/// <summary>Named support-score deltas — not calibrated probabilities.</summary>
file static class SupportDelta
{
    public const int ConfirmSupport = 8;
    public const int PartialSupport = 6;
    public const int AbnormalExitSupport = 4;
    public const int SafeAdjacentSupport = 12;
    public const int WeakenPenalty = 12;
    public const int RefutePenalty = 20;
    public const int WrongSignaturePenalty = 10;
    public const int PatternDepthBonus = 12;
    public const int HighInfluenceBonus = 8;
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
    int RemainingBudget = 3,
    string? TypeId = null)
{
    public int SupportScore => ConfidencePercent;
};
