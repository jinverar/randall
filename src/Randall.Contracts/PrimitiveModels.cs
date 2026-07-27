namespace Randall.Contracts;

/// <summary>
/// How strongly a bug-capability (primitive) is supported by evidence.
/// Mirrors <see cref="InfluenceConfirmationStatus"/> so influence links map 1:1.
/// Research/teaching taxonomy — describes what state a crash lets you observe or
/// influence, never a weaponized exploit primitive.
/// </summary>
public enum PrimitiveState
{
    /// <summary>Directly observed in debugger / corruption chain / influence link.</summary>
    Observed,
    /// <summary>A deterministic replay / hypothesis experiment confirmed the capability.</summary>
    Confirmed,
    /// <summary>Inferred or partially supported — experiment pending.</summary>
    Candidate,
    Unknown,
}

/// <summary>
/// Category of bug capability assessed from confirmed evidence — research/teaching only.
/// These describe <em>what the crash lets a researcher observe or influence</em>
/// (read/write locality, length/size control, pointer/lifetime influence). They are
/// NOT exploit primitives, payloads, ROP, or write-what-where weaponization.
/// </summary>
public enum PrimitiveKind
{
    Unknown,
    /// <summary>Read occurs at an input-influenced address.</summary>
    InputInfluencedRead,
    /// <summary>Write occurs at an input-influenced address.</summary>
    InputInfluencedWrite,
    /// <summary>A pointer value is derived from input bytes.</summary>
    PointerControl,
    /// <summary>The instruction pointer / return address reflects input bytes.</summary>
    InstructionPointerInfluence,
    /// <summary>A general-purpose register value is derived from input.</summary>
    RegisterControl,
    /// <summary>A read/receive length is influenced by input.</summary>
    LengthControl,
    /// <summary>A copy/store length is influenced by input (over-copy study).</summary>
    WriteLengthControl,
    /// <summary>An allocation size is influenced by input.</summary>
    AllocationSizeControl,
    /// <summary>Object lifetime (free/reuse) is influenced by input (UAF study).</summary>
    ObjectLifetimeInfluence,
    /// <summary>Parser/state-machine transition is influenced by input.</summary>
    ParserStateInfluence,
}

/// <summary>
/// Educational research-maturity level for a crash / research finding (R0…R7).
/// This is a <em>study-depth</em> ladder — how well the crash is understood as a
/// research artifact — NOT a measure of exploit completion or weaponization.
/// </summary>
public enum ResearchMaturity
{
    /// <summary>R0 — Discovered: a crash was reproduced/observed, no analysis yet.</summary>
    R0,
    /// <summary>R1 — Triaged: fault classified (signal / severity / faulting site).</summary>
    R1,
    /// <summary>R2 — Root-caused: a deterministic root-cause category is assigned.</summary>
    R2,
    /// <summary>R3 — Input-attributed: an input region is linked to influenced state.</summary>
    R3,
    /// <summary>R4 — Primitive candidate: at least one capability primitive is inferred.</summary>
    R4,
    /// <summary>R5 — Primitive observed: a capability is directly observed in evidence.</summary>
    R5,
    /// <summary>R6 — Primitive confirmed: a capability is experimentally confirmed.</summary>
    R6,
    /// <summary>R7 — Research-mature: multiple confirmed capabilities + high-confidence root cause.</summary>
    R7,
}

/// <summary>
/// One assessed bug capability for a crash — research/teaching only.
/// </summary>
public sealed record PrimitiveAssessmentDto(
    /// <summary>Stable id, e.g. <c>prim-write-28</c>.</summary>
    string Id,
    PrimitiveKind Kind,
    PrimitiveState State,
    /// <summary>0–1 confidence for this capability alone.</summary>
    double Confidence,
    /// <summary>Plain-language mechanism, e.g. "input controls store address".</summary>
    string Mechanism,
    /// <summary>Input region driving the capability, when attributed.</summary>
    InfluenceRegionDto? Region,
    /// <summary>Evidence fact names / tags supporting this assessment.</summary>
    IReadOnlyList<string> EvidenceRefs,
    /// <summary>Related influence link id, when derived from one.</summary>
    string? InfluenceLinkId = null,
    /// <summary>Related hypothesis id, when a confirming experiment exists.</summary>
    string? HypothesisId = null);

/// <summary>
/// Capability assessment rollup for one crash — persisted as <c>{guid}_primitives.json</c>.
/// Aggregates influence links, root cause, and debugger evidence into a research
/// maturity level (R0–R7) and a list of assessed capabilities. Research-only.
/// </summary>
public sealed record CrashPrimitiveReportDto(
    bool Ok,
    Guid CrashId,
    string Project,
    ResearchMaturity Maturity,
    /// <summary>Short human label, e.g. "Primitive observed".</summary>
    string MaturityLabel,
    /// <summary>Why this level was reached (deterministic rationale).</summary>
    string MaturityRationale,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN rollup across capabilities.</summary>
    string Confidence,
    string Summary,
    IReadOnlyList<PrimitiveAssessmentDto> Primitives,
    IReadOnlyList<EvidenceFact> Facts,
    DateTimeOffset At,
    string? Error = null,
    /// <summary>JSON schema version for persisted research artifacts (v1). Absent on legacy files → default 1.</summary>
    int SchemaVersion = 1,
    /// <summary>Randall analysis-engine identity at write time (optional on legacy files).</summary>
    RandallBuildIdentityDto? Engine = null);
