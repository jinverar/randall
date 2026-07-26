namespace Randall.Contracts;

/// <summary>Deterministic root-cause category — assigned only when evidence supports it.</summary>
public enum RootCauseCategory
{
    Unknown,
    BoundsViolation,
    IntegerConversion,
    SizeMismatch,
    LifetimeViolation,
    UnexpectedObjectState,
    Uninitialized,
    ParserState,
    FormatInterpretation,
}

/// <summary>
/// Primary root-cause hypothesis for one crash — research-only, no exploit automation.
/// </summary>
public sealed record RootCauseCandidate(
    RootCauseCategory Category,
    string? FaultingFunction,
    string? SuspectedSourceFunction,
    string? SuspectedSink,
    string? InputRegion,
    string? AllocationSite,
    string? CorruptionSite,
    IReadOnlyList<EvidenceFact> Evidence,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN</summary>
    string Confidence,
    IReadOnlyList<string> ObservedFacts,
    IReadOnlyList<string> Inferences,
    IReadOnlyList<string> Unknowns);

/// <summary>
/// Root-cause analysis rollup — persisted as <c>{guid}_root_cause.json</c>.
/// </summary>
public sealed record RootCauseAnalysisDto(
    bool Ok,
    Guid CrashId,
    string Project,
    RootCauseCandidate Candidate,
    /// <summary>Plain-language teaching summary for Investigation UI.</summary>
    string EducationalSummary,
    IReadOnlyList<RootCauseCandidate>? Alternatives = null,
    DateTimeOffset At = default,
    string? Error = null);
