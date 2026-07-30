namespace Randall.Contracts;

/// <summary>
/// How a fact was established — research-only taxonomy (no exploit automation).
/// </summary>
public enum EvidenceObservationType
{
    /// <summary>Read directly from a sensor transcript or sidecar field.</summary>
    Observed,
    /// <summary>Confirmed by a deterministic replay / experiment.</summary>
    ExperimentallyConfirmed,
    /// <summary>Heuristic join across sensors (attribution, address class, chain step).</summary>
    Inferred,
    /// <summary>Ranked hypothesis or untested theory from the Hypothesis Engine.</summary>
    Hypothesized,
}

/// <summary>
/// Normalized evidence atom for crash investigation and downstream root-cause / primitive layers.
/// All engines should emit or adapt into this shape — consumers read <see cref="CrashEvidenceDto.Facts"/> only.
/// </summary>
public sealed record EvidenceFact(
    /// <summary>Stable field key, e.g. <c>faultAddress</c>, <c>corruption.confidence</c>, <c>hypothesis.H1</c>.</summary>
    string Name,
    /// <summary>Human-readable value (hex address, enum label, summary line).</summary>
    string? Value,
    /// <summary>Provenance sensor: <c>debugger</c>, <c>corruption_chain</c>, <c>oracle</c>, …</summary>
    string Source,
    /// <summary>Optional artifact path or CDB command, e.g. <c>.exr -1</c> or <c>{guid}_debugger_observation.json</c>.</summary>
    string? SourceArtifact,
    EvidenceObservationType ObservationType,
    /// <summary>0–1 confidence for this fact alone.</summary>
    double Confidence,
    DateTimeOffset Timestamp,
    /// <summary>Related fact <see cref="Name"/> values for cross-linking in Investigation UI.</summary>
    IReadOnlyList<string>? RelatedFacts = null);

/// <summary>
/// Persisted evidence rollup for one crash — <c>{guid}_evidence.json</c> beside other triage artifacts.
/// </summary>
public sealed record CrashEvidenceDto(
    bool Ok,
    Guid CrashId,
    string Project,
    IReadOnlyList<EvidenceFact> Facts,
    DateTimeOffset At,
    string? Error = null,
    /// <summary>JSON schema version for persisted research artifacts (v1). Absent on legacy files → default 1.</summary>
    int SchemaVersion = 1,
    /// <summary>Randall analysis-engine identity at write time (optional on legacy files).</summary>
    RandallBuildIdentityDto? Engine = null,
    /// <summary>Crash artifact identity envelope when known.</summary>
    CrashArtifactIdentity? ArtifactIdentity = null,
    /// <summary>Join integrity after ValidateIdentity (Rejected blocks strong promotion).</summary>
    ArtifactIntegrityStatus IntegrityStatus = ArtifactIntegrityStatus.Unverified,
    /// <summary>Validation summary / secondary-exception classification.</summary>
    ArtifactValidationResult? Validation = null);
