namespace Randall.Contracts;

/// <summary>How strongly an input→state influence link is supported.</summary>
public enum InfluenceConfirmationStatus
{
    /// <summary>Directly observed in debugger / corruption chain / register match.</summary>
    Observed,
    /// <summary>Hypothesis experiment confirmed the influence.</summary>
    Confirmed,
    /// <summary>Inferred or partially supported — experiment pending.</summary>
    Candidate,
    Unknown,
}

/// <summary>Program state category influenced by an input region.</summary>
public enum InfluencedStateKind
{
    FaultAddress,
    Register,
    Length,
    Pointer,
    AllocationSize,
    CopyLength,
    HeapObject,
    ParserState,
    Unknown,
}

/// <summary>Byte range in the crash input suspected to drive program state.</summary>
public sealed record InfluenceRegionDto(
    int StartOffset,
    int? EndOffset,
    int? WidthBytes,
    string? FieldLabel,
    string? Mutator,
    int? MutatorStepIndex);

/// <summary>Program state influenced by an input region.</summary>
public sealed record InfluencedStateDto(
    InfluencedStateKind Kind,
    string Label,
    string? Value = null,
    string? Detail = null);

/// <summary>
/// One directed link: input region → influenced state, with confirmation and evidence refs.
/// Research-only — teaches control of state, not exploit payloads.
/// </summary>
public sealed record InfluenceLinkDto(
    string Id,
    InfluenceRegionDto Region,
    InfluencedStateDto State,
    InfluenceConfirmationStatus Status,
    /// <summary>e.g. length→alloc/copy, pointer→fault address, register→sink</summary>
    string Mechanism,
    IReadOnlyList<string> EvidenceRefs,
    HypothesisExperimentDto? SuggestedExperiment = null,
    string? HypothesisId = null);

/// <summary>
/// Systematic map of input regions to program state — persisted as <c>{guid}_influence.json</c>.
/// </summary>
public sealed record CrashInfluenceMapDto(
    bool Ok,
    Guid CrashId,
    string Project,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN rollup.</summary>
    string Confidence,
    string Summary,
    IReadOnlyList<InfluenceLinkDto> Links,
    IReadOnlyList<EvidenceFact> Facts,
    DateTimeOffset At,
    string? Narrative = null,
    string? Error = null,
    /// <summary>JSON schema version for persisted research artifacts (v1). Absent on legacy files → default 1.</summary>
    int SchemaVersion = 1);
