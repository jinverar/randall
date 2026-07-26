#!/usr/bin/env python3
"""Apply mature Hypothesis Engine scientific loop in one atomic pass."""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]


def patch_hypothesis_models() -> None:
    path = ROOT / "src/Randall.Contracts/HypothesisModels.cs"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        "    DateTimeOffset At);",
        "    DateTimeOffset At,\n    int? ConfidenceBefore = null);",
        1,
    )
    text = text.replace(
        "persisted as <c>{guid}_hypotheses.json</c>",
        "persisted under <c>_hypotheses/{guid}.json</c>",
    )
    if "HypothesisLedgerEntryDto" not in text:
        text = text.replace(
            "    HypothesisDto? TopHypothesis);",
            """    HypothesisDto? TopHypothesis);

/// <summary>One row in the project hypothesis ledger (<c>_hypotheses/ledger.json</c>).</summary>
public sealed record HypothesisLedgerEntryDto(
    string HypothesisId,
    Guid CrashId,
    string Statement,
    int ConfidencePercent,
    HypothesisStatus Status,
    HypothesisExperimentKind ExperimentKind,
    HypothesisResultDto? Result,
    DateTimeOffset At);

/// <summary>Project-level hypothesis ledger — aggregated view for Investigation and Hunt Policy.</summary>
public sealed record HypothesisProjectLedgerDto(
    string Project,
    int Iteration,
    DateTimeOffset At,
    IReadOnlyList<HypothesisLedgerEntryDto> Entries,
    HypothesisDto? TopPending,
    HypothesisProjectSnapshotDto? Queue = null);""",
        )
    path.write_text(text, encoding="utf-8")


def patch_hypothesis_engine() -> None:
    path = ROOT / "src/Randall.Infrastructure/HypothesisEngine.cs"
    src = path.read_text(encoding="utf-8")
    if "TryReadForCrash" in src:
        return

    src = src.replace(
        "using Randall.Contracts;",
        "using Randall.Contracts;\nusing Randall.Core;",
    )
    src = src.replace(
        '    public const string QueueFileName = "hypothesis_queue.json";',
        '    public const string QueueFileName = "hypothesis_queue.json";\n'
        '    public const string LedgerFileName = "ledger.json";',
    )
    src = src.replace(
        "    public static string PathFor(string crashesDir, Guid crashId) =>\n"
        "        Path.Combine(crashesDir, $\"{crashId:N}_hypotheses.json\");",
        """    public static string LedgerDir(string crashesDir) => Path.Combine(crashesDir, "_hypotheses");
    public static string PathFor(string crashesDir, Guid crashId) => Path.Combine(LedgerDir(crashesDir), $"{crashId:N}.json");
    public static string LegacyPathFor(string crashesDir, Guid crashId) => Path.Combine(crashesDir, $"{crashId:N}_hypotheses.json");
    public static string LedgerPath(string crashesDir) => Path.Combine(LedgerDir(crashesDir), LedgerFileName);""",
    )

    insert = '''
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
'''
    src = src.replace("    public static HypothesisSetDto Build(", insert + "\n    public static HypothesisSetDto Build(", 1)

    src = src.replace(
        "        Directory.CreateDirectory(crashesDir);\n"
        "        var path = PathFor(crashesDir, set.CrashId);\n"
        "        File.WriteAllText(path, JsonSerializer.Serialize(set, JsonOptions));\n"
        "        return path;",
        "        Directory.CreateDirectory(LedgerDir(crashesDir));\n"
        "        var path = PathFor(crashesDir, set.CrashId);\n"
        "        File.WriteAllText(path, JsonSerializer.Serialize(set, JsonOptions));\n"
        "        SyncProjectLedger(set.Project, crashesDir, TryLoadQueue(set.Project)?.Iteration ?? 0);\n"
        "        return path;",
    )

    src = re.sub(
        r"HypothesisDto\? best = null;\s*foreach \(var file in Directory\.EnumerateFiles\(crashesDir, \"\*_hypotheses\.json\"\)\)\s*\{[^}]+\}",
        "HypothesisDto? best = null;\n        foreach (var set in EnumerateProjectSets(crashesDir))\n        {\n"
        "            var top = TopPending(set);\n"
        "            if (top is null) continue;\n"
        "            if (best is null || top.ConfidencePercent > best.ConfidencePercent) best = top;\n"
        "        }",
        src,
        count=1,
    )

    src = src.replace(
        "            inputPath,\n            entry.RemainingBudget);\n\n        if (crashesDir is not null)\n            MarkRunning(crashesDir, entry.CrashId, entry.HypothesisId);",
        "            inputPath,\n            entry.RemainingBudget);",
    )
    src = src.replace(
        "        var inputPath = crashesDir is null\n            ? null\n            : FindCrashInputPath(crashesDir, entry.CrashId);\n\n        return new HypothesisExperimentPlan(",
        "        var inputPath = crashesDir is null\n            ? null\n            : FindCrashInputPath(crashesDir, entry.CrashId);\n\n"
        "        if (crashesDir is not null)\n            MarkRunning(crashesDir, entry.CrashId, entry.HypothesisId);\n\n"
        "        return new HypothesisExperimentPlan(",
    )

    mark_running = '''
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
'''
    src = src.replace("    public static void EnqueueFromHypothesis(", mark_running + "\n    public static void EnqueueFromHypothesis(", 1)

    src = re.sub(
        r"public static byte\[\]\? ApplyExperiment\([\s\S]*?\n    \}\n\n    public static void RecordOutcome",
        '''public static byte[]? ApplyExperiment(byte[] basePayload, HypothesisExperimentDto experiment, int sweepIndex, Random rng, IReadOnlyList<IMutator>? mutators = null)
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

    public static void RecordOutcome''',
        src,
        count=1,
    )

    src = src.replace(
        "        var setPath = PathFor(crashesDir, plan.CrashId);\n        var set = TryRead(setPath);",
        "        var set = TryReadForCrash(crashesDir, plan.CrashId);",
    )
    src = src.replace(
        "        var (status, confidence, observation) = EvaluateOutcome(\n            hyp, plan, crashed, crashClass, faultDetail);",
        "        var confidenceBefore = hyp.ConfidencePercent;\n"
        "        var remainingAfter = plan.RemainingBudget - 1;\n"
        "        var (status, confidence, observation) = EvaluateOutcome(hyp, crashed, crashClass, faultDetail, remainingAfter);",
    )
    src = src.replace(
        "            Result = new HypothesisResultDto(status, confidence, observation, iteration, DateTimeOffset.UtcNow),",
        "            Result = new HypothesisResultDto(status, confidence, observation, iteration, DateTimeOffset.UtcNow, confidenceBefore),",
    )
    src = src.replace("        var remaining = entry.RemainingBudget - 1;", "        var remaining = remainingAfter;")

    src = src.replace(
        "        File.WriteAllText(path, JsonSerializer.Serialize(snap, JsonOptions));\n    }\n\n    public static string FormatVerbose",
        "        File.WriteAllText(path, JsonSerializer.Serialize(snap, JsonOptions));\n\n"
        "        var repo = repoRoot ?? CrashCatalog.FindRepoRoot();\n"
        "        if (repo is not null)\n        {\n"
        "            var crashesDir = Path.Combine(repo, \"data\", \"crashes\", project);\n"
        "            if (Directory.Exists(crashesDir))\n"
        "                SyncProjectLedger(project, crashesDir, iteration, repoRoot);\n"
        "        }\n    }\n\n    public static string FormatVerbose",
    )

    helpers = '''
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
'''
    src = src.replace("    private static byte[] ApplyBoundaryProbe", helpers + "\n    private static byte[] ApplyBoundaryProbe")

    src = re.sub(
        r"private static byte\[\] ApplyBoundaryProbe\(byte\[\] payload, HypothesisExperimentDto experiment\)\s*\{[\s\S]*?return copy;\s*\}",
        '''private static byte[] ApplyBoundaryProbe(byte[] payload, HypothesisExperimentDto experiment, int sweepIndex)
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
    }''',
        src,
        count=1,
    )

    src = re.sub(
        r"private static \(HypothesisStatus Status, int Confidence, string Observation\) EvaluateOutcome\([\s\S]*?\n    \}\n\n    private static void RemoveQueueEntry",
        '''private static (HypothesisStatus Status, int Confidence, string Observation) EvaluateOutcome(
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

    private static void RemoveQueueEntry''',
        src,
        count=1,
    )

    src = src.replace("    string? CrashInputPath);", "    string? CrashInputPath,\n    int RemainingBudget = 3);")
    path.write_text(src, encoding="utf-8")


def patch_fuzz_engine() -> None:
    path = ROOT / "src/Randall.Infrastructure/FuzzEngine.cs"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        "hypothesisPlan.Experiment, hypothesisPlan.SweepIndex, rng)",
        "hypothesisPlan.Experiment, hypothesisPlan.SweepIndex, rng, mutators)",
    )
    text = text.replace(
        "HypothesisEngine.TryRead(HypothesisEngine.PathFor(crashesDir, saved.Id))",
        "HypothesisEngine.TryReadForCrash(crashesDir, saved.Id)",
    )
    path.write_text(text, encoding="utf-8")


def patch_crash_catalog() -> None:
    path = ROOT / "src/Randall.Infrastructure/CrashCatalog.cs"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        "HypothesisEngine.TryRead(\n                    HypothesisEngine.PathFor(dir, row.Summary.Id))",
        "HypothesisEngine.TryReadForCrash(dir, row.Summary.Id)",
    )
    text = text.replace(
        "HypothesisEngine.TryRead(\n                HypothesisEngine.PathFor(crashesDir, summary.Id))",
        "HypothesisEngine.TryReadForCrash(crashesDir, summary.Id)",
    )
    path.write_text(text, encoding="utf-8")


def patch_program() -> None:
    path = ROOT / "src/Randall.Server/Program.cs"
    text = path.read_text(encoding="utf-8")
    if "TryLoadLedger" in text:
        return
    text = text.replace(
        "        var top = HypothesisEngine.FindTopForProject(project);\n        return Results.Ok(new\n        {\n            project,\n            queue,\n            topHypothesis = top,\n        });",
        "        var top = HypothesisEngine.FindTopForProject(project);\n"
        "        var repo = CrashCatalog.FindRepoRoot();\n"
        "        var crashesDir = repo is null ? null : Path.Combine(repo, \"data\", \"crashes\", project);\n"
        "        var ledger = crashesDir is not null && Directory.Exists(crashesDir) ? HypothesisEngine.TryLoadLedger(crashesDir) : null;\n"
        "        return Results.Ok(new { project, queue, topHypothesis = top, ledger });",
    )
    path.write_text(text, encoding="utf-8")


def main() -> None:
    patch_hypothesis_models()
    patch_hypothesis_engine()
    patch_fuzz_engine()
    patch_crash_catalog()
    patch_program()
    print("hypothesis mature patch applied")


if __name__ == "__main__":
    main()
