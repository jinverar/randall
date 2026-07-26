namespace Randall.Contracts;

/// <summary>
/// One step in a dump-only backward trace (research exploit narrative — no live TTD).
/// Typical order: mutation → register → stack/heap source → fault instruction → crash.
/// </summary>
public sealed record BackwardTraceStepDto(
    int Order,
    string Kind,
    string Label,
    string? Detail = null,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN — heuristic confidence for this step.</summary>
    string Confidence = "UNKNOWN");

/// <summary>
/// Post-mortem backward trace from CDB/dump probes joined with mutation lineage.
/// Persisted as <c>{guid}_backward_trace.json</c>.
/// </summary>
public sealed record CrashBackwardTraceDto(
    bool Ok,
    Guid CrashId,
    string Project,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN</summary>
    string Confidence,
    /// <summary>One-paragraph exploit research story (field → mutator → register → sink → AV).</summary>
    string Story,
    IReadOnlyList<BackwardTraceStepDto> Steps,
    string? FaultInstruction,
    string? FaultRegister,
    string? BadPointerSource,
    string? SuspectedMutator,
    int? SuspectedMutatorStep,
    string? PrimaryPayloadOffset,
    IReadOnlyList<RegisterPayloadMatchDto>? RegisterMatches = null,
    string? HeapTimeline = null,
    DateTimeOffset At = default,
    string? Error = null);
