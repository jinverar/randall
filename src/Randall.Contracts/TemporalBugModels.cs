namespace Randall.Contracts;

/// <summary>
/// High-level temporal phase for educational crash timelines:
/// Corruption → Crash → RootCause attribution notes.
/// </summary>
public enum TemporalPhase
{
    Corruption,
    Crash,
    RootCause,
}

/// <summary>One ordered step in a temporal bug timeline (teaching narrative).</summary>
public sealed record TimelineEntryDto(
    int Order,
    TemporalPhase Phase,
    string Label,
    string? Detail = null,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN</summary>
    string Confidence = "UNKNOWN");

/// <summary>
/// Temporal bug reasoning rollup — educational timeline from corruption through
/// crash to root-cause attribution. Mentions Deep Scream / TTD playbook notes when
/// a deep-scream mark is present (notes only — no auto-exploit).
/// Persisted as <c>{guid}_temporal.json</c>.
/// </summary>
public sealed record TemporalBugReportDto(
    bool Ok,
    Guid CrashId,
    string Project,
    string Summary,
    IReadOnlyList<TimelineEntryDto> Timeline,
    /// <summary>Deep Scream / TTD / Rewind teaching playbook notes when marked.</summary>
    string? DeepScreamPlaybookNotes = null,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN</summary>
    string Confidence = "UNKNOWN",
    DateTimeOffset At = default,
    string? Error = null);
