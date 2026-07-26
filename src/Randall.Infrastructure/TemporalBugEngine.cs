using System.Text;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Temporal Bug Reasoning — builds an educational Corruption → Crash → RootCause
/// timeline from backward trace, corruption chain, root cause, and optional Deep Scream.
/// Teaching notes only (TTD / Rewind playbook mentions); no auto-exploit.
/// </summary>
public static class TemporalBugEngine
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    public static string PathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_temporal.json");

    public static TemporalBugReportDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<TemporalBugReportDto>(File.ReadAllText(path), JsonOpts);
        }
        catch
        {
            return null;
        }
    }

    public static TemporalBugReportDto? TryReadForCrash(string crashesDir, Guid crashId) =>
        TryRead(PathFor(crashesDir, crashId));

    public static TemporalBugReportDto Build(
        Guid crashId,
        string project,
        CrashBackwardTraceDto? backwardTrace,
        CrashCorruptionChainDto? corruptionChain,
        RootCauseAnalysisDto? rootCause,
        DeepScreamDto? deepScream = null)
    {
        var hasAny = backwardTrace is { Ok: true }
            || corruptionChain is { Ok: true }
            || rootCause is { Ok: true }
            || deepScream is { Ok: true };

        if (!hasAny)
        {
            return new TemporalBugReportDto(
                false,
                crashId,
                project,
                "Insufficient evidence for a temporal timeline — need a corruption chain, backward trace, or root-cause analysis.",
                [],
                null,
                "UNKNOWN",
                DateTimeOffset.UtcNow,
                Error: "no correlatable evidence");
        }

        var timeline = BuildTimeline(backwardTrace, corruptionChain, rootCause);
        var confidence = RollupConfidence(backwardTrace, corruptionChain, rootCause);
        var playbook = BuildDeepScreamPlaybookNotes(deepScream);
        var summary = BuildSummary(timeline, rootCause, corruptionChain, backwardTrace, playbook);

        return new TemporalBugReportDto(
            timeline.Count > 0,
            crashId,
            project,
            summary,
            timeline,
            playbook,
            confidence,
            DateTimeOffset.UtcNow);
    }

    public static TemporalBugReportDto PersistForCrash(
        string crashesDir,
        Guid crashId,
        string project,
        CrashBackwardTraceDto? backwardTrace,
        CrashCorruptionChainDto? corruptionChain,
        RootCauseAnalysisDto? rootCause,
        DeepScreamDto? deepScream = null)
    {
        var report = Build(crashId, project, backwardTrace, corruptionChain, rootCause, deepScream);
        Write(crashesDir, report);
        return report;
    }

    public static string Write(string crashesDir, TemporalBugReportDto report)
    {
        Directory.CreateDirectory(crashesDir);
        var path = PathFor(crashesDir, report.CrashId);
        File.WriteAllText(path, JsonSerializer.Serialize(report, JsonOpts));
        return path;
    }

    private static List<TimelineEntryDto> BuildTimeline(
        CrashBackwardTraceDto? backwardTrace,
        CrashCorruptionChainDto? corruptionChain,
        RootCauseAnalysisDto? rootCause)
    {
        var entries = new List<TimelineEntryDto>();
        var order = 0;

        // Phase 1 — Corruption (input → tainted state)
        if (corruptionChain is { Ok: true, Steps.Count: > 0 })
        {
            foreach (var step in corruptionChain.Steps.OrderBy(s => s.Order).Take(6))
            {
                entries.Add(new TimelineEntryDto(
                    ++order,
                    TemporalPhase.Corruption,
                    step.Label,
                    step.Detail ?? corruptionChain.Summary,
                    corruptionChain.Confidence));
            }
        }
        else if (backwardTrace is { Ok: true, Steps.Count: > 0 })
        {
            foreach (var step in backwardTrace.Steps
                         .Where(s => IsCorruptionKind(s.Kind))
                         .OrderBy(s => s.Order)
                         .Take(4))
            {
                entries.Add(new TimelineEntryDto(
                    ++order,
                    TemporalPhase.Corruption,
                    step.Label,
                    step.Detail,
                    step.Confidence));
            }
        }

        if (entries.All(e => e.Phase != TemporalPhase.Corruption))
        {
            var label = !string.IsNullOrWhiteSpace(corruptionChain?.SuspectedField)
                ? $"Input field '{corruptionChain!.SuspectedField}' influences program state"
                : !string.IsNullOrWhiteSpace(backwardTrace?.SuspectedMutator)
                    ? $"Mutator '{backwardTrace!.SuspectedMutator}' contributes to tainted state"
                    : "Suspected corruption precedes the observable fault";
            entries.Add(new TimelineEntryDto(
                ++order,
                TemporalPhase.Corruption,
                label,
                corruptionChain?.Narrative ?? backwardTrace?.Story,
                corruptionChain?.Confidence ?? backwardTrace?.Confidence ?? "LOW"));
        }

        // Phase 2 — Crash (fault observation)
        if (backwardTrace is { Ok: true })
        {
            var faultLabel = !string.IsNullOrWhiteSpace(backwardTrace.FaultInstruction)
                ? $"Fault at {backwardTrace.FaultInstruction}"
                : "Observable crash / fault";
            var detail = new StringBuilder();
            if (!string.IsNullOrWhiteSpace(backwardTrace.FaultRegister))
                detail.Append($"register {backwardTrace.FaultRegister}; ");
            if (!string.IsNullOrWhiteSpace(backwardTrace.BadPointerSource))
                detail.Append($"bad pointer from {backwardTrace.BadPointerSource}; ");
            if (!string.IsNullOrWhiteSpace(backwardTrace.PrimaryPayloadOffset))
                detail.Append($"payload offset {backwardTrace.PrimaryPayloadOffset}");

            entries.Add(new TimelineEntryDto(
                ++order,
                TemporalPhase.Crash,
                faultLabel,
                detail.Length > 0 ? detail.ToString().Trim().TrimEnd(';') : backwardTrace.Story,
                backwardTrace.Confidence));

            foreach (var step in backwardTrace.Steps
                         .Where(s => IsCrashKind(s.Kind))
                         .OrderBy(s => s.Order)
                         .Take(3))
            {
                entries.Add(new TimelineEntryDto(
                    ++order,
                    TemporalPhase.Crash,
                    step.Label,
                    step.Detail,
                    step.Confidence));
            }
        }
        else if (corruptionChain is { Ok: true })
        {
            entries.Add(new TimelineEntryDto(
                ++order,
                TemporalPhase.Crash,
                "Crash observed after corruption chain",
                corruptionChain.DebuggerDiagnosis ?? corruptionChain.Summary,
                corruptionChain.Confidence));
        }
        else
        {
            entries.Add(new TimelineEntryDto(
                ++order,
                TemporalPhase.Crash,
                "Crash observed",
                null,
                "LOW"));
        }

        // Phase 3 — RootCause attribution notes
        if (rootCause is { Ok: true })
        {
            var c = rootCause.Candidate;
            entries.Add(new TimelineEntryDto(
                ++order,
                TemporalPhase.RootCause,
                $"Attributed as {c.Category} ({c.Confidence})",
                rootCause.EducationalSummary,
                c.Confidence));

            foreach (var inference in c.Inferences.Take(3))
            {
                entries.Add(new TimelineEntryDto(
                    ++order,
                    TemporalPhase.RootCause,
                    "Inference",
                    inference,
                    c.Confidence));
            }

            foreach (var unknown in c.Unknowns.Take(2))
            {
                entries.Add(new TimelineEntryDto(
                    ++order,
                    TemporalPhase.RootCause,
                    "Unknown / open question",
                    unknown,
                    "LOW"));
            }
        }
        else
        {
            entries.Add(new TimelineEntryDto(
                ++order,
                TemporalPhase.RootCause,
                "Root-cause attribution pending",
                "Run RootCauseEngine once triage/debugger evidence is available.",
                "UNKNOWN"));
        }

        return entries;
    }

    private static bool IsCorruptionKind(string kind) =>
        kind.Contains("mutat", StringComparison.OrdinalIgnoreCase)
        || kind.Contains("input", StringComparison.OrdinalIgnoreCase)
        || kind.Contains("register", StringComparison.OrdinalIgnoreCase)
        || kind.Contains("heap", StringComparison.OrdinalIgnoreCase)
        || kind.Contains("alloc", StringComparison.OrdinalIgnoreCase)
        || kind.Contains("field", StringComparison.OrdinalIgnoreCase);

    private static bool IsCrashKind(string kind) =>
        kind.Contains("fault", StringComparison.OrdinalIgnoreCase)
        || kind.Contains("crash", StringComparison.OrdinalIgnoreCase)
        || kind.Contains("av", StringComparison.OrdinalIgnoreCase)
        || kind.Contains("exception", StringComparison.OrdinalIgnoreCase)
        || kind.Contains("sink", StringComparison.OrdinalIgnoreCase);

    private static string RollupConfidence(
        CrashBackwardTraceDto? backwardTrace,
        CrashCorruptionChainDto? corruptionChain,
        RootCauseAnalysisDto? rootCause)
    {
        var scores = new List<int>();
        void Rank(string? c)
        {
            scores.Add(c?.ToUpperInvariant() switch
            {
                "HIGH" => 3,
                "MEDIUM" => 2,
                "LOW" => 1,
                _ => 0,
            });
        }

        Rank(backwardTrace?.Confidence);
        Rank(corruptionChain?.Confidence);
        Rank(rootCause?.Candidate.Confidence);

        if (scores.Count == 0)
            return "UNKNOWN";
        var avg = scores.Average();
        return avg >= 2.5 ? "HIGH" : avg >= 1.5 ? "MEDIUM" : avg > 0 ? "LOW" : "UNKNOWN";
    }

    private static string? BuildDeepScreamPlaybookNotes(DeepScreamDto? deepScream)
    {
        if (deepScream is not { Ok: true })
            return null;

        if (!deepScream.IsMarked && !deepScream.IsCandidate)
            return null;

        var sb = new StringBuilder();
        sb.Append(
            "Deep Scream / TTD playbook (teaching notes): this scream is marked or eligible for the " +
            "expensive rewind path. Prefer Time Travel Debugging (TTD) or Rewind Scream to step " +
            "backward from the crash to the first corrupting write — annotate the timeline, do not " +
            "auto-exploit.");

        if (deepScream.TtdToolsPresent)
            sb.Append(" TTD tools appear present on this host.");
        else if (!string.IsNullOrWhiteSpace(deepScream.TtdToolsSummary))
            sb.Append($" Tooling note: {deepScream.TtdToolsSummary}");

        if (!string.IsNullOrWhiteSpace(deepScream.TtdLaunchNote))
            sb.Append($" Launch note: {deepScream.TtdLaunchNote}");
        if (!string.IsNullOrWhiteSpace(deepScream.TtdHintPath))
            sb.Append($" Hint artifact: {deepScream.TtdHintPath}");
        if (!string.IsNullOrWhiteSpace(deepScream.TtdRecordScriptPath))
            sb.Append($" Record script path (operator): {deepScream.TtdRecordScriptPath}");
        if (!string.IsNullOrWhiteSpace(deepScream.TtdReplayScriptPath))
            sb.Append($" Replay script path (operator): {deepScream.TtdReplayScriptPath}");

        sb.Append(" Notes only — Randall does not generate payloads or automate exploitation.");
        return sb.ToString();
    }

    private static string BuildSummary(
        IReadOnlyList<TimelineEntryDto> timeline,
        RootCauseAnalysisDto? rootCause,
        CrashCorruptionChainDto? corruptionChain,
        CrashBackwardTraceDto? backwardTrace,
        string? playbook)
    {
        var corr = timeline.Count(e => e.Phase == TemporalPhase.Corruption);
        var crash = timeline.Count(e => e.Phase == TemporalPhase.Crash);
        var rca = timeline.Count(e => e.Phase == TemporalPhase.RootCause);
        var cat = rootCause?.Candidate.Category.ToString() ?? "unattributed";

        var sb = new StringBuilder();
        sb.Append(
            $"Temporal timeline: {corr} corruption → {crash} crash → {rca} root-cause note(s); " +
            $"primary attribution {cat}.");

        if (!string.IsNullOrWhiteSpace(corruptionChain?.Summary))
            sb.Append($" Chain: {Truncate(corruptionChain.Summary, 100)}");
        else if (!string.IsNullOrWhiteSpace(backwardTrace?.Story))
            sb.Append($" Trace: {Truncate(backwardTrace.Story, 100)}");

        if (!string.IsNullOrWhiteSpace(playbook))
            sb.Append(" Deep Scream TTD/Rewind playbook notes attached.");

        return sb.ToString();
    }

    private static string Truncate(string text, int max) =>
        text.Length <= max ? text : text[..(max - 1)] + "…";
}
