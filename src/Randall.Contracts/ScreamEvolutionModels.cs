namespace Randall.Contracts;

/// <summary>
/// Coarse bug-progression ladder for scream evolution momentum (research triage only).
/// Higher rank = "warmer" phenotype vs ancestors (e.g. READ → WRITE → controlled WRITE).
/// </summary>
public enum ScreamProgressionStep
{
    Unknown = 0,
    ReadViolation = 1,
    WriteViolation = 2,
    ExecuteViolation = 3,
    ControlledAddress = 4,
    PatternDepth = 5,
}

/// <summary>
/// Persisted scream-family / momentum / generation state for one crash.
/// Written as <c>{guid}_scream_evolution.json</c> next to other crash sidecars.
/// </summary>
public sealed record ScreamEvolutionDto(
    bool Ok,
    Guid CrashId,
    string Project,
    /// <summary>Stable family key grouping phenotype (function + stack + seed root — not IP cluster alone).</summary>
    string FamilyId,
    string? FamilyLabel,
    /// <summary>1 = root seed crash; N = derived from ancestor input hash.</summary>
    int Generation,
    Guid? AncestorCrashId,
    string? AncestorInputHash,
    /// <summary>0–100 — improvement vs best ancestor in the family.</summary>
    int MomentumScore,
    /// <summary>stable | warming | hot | cooling</summary>
    string MomentumLabel,
    ScreamProgressionStep ProgressionStep,
    ScreamProgressionStep? AncestorProgressionStep,
    /// <summary>Signed step delta vs ancestor (positive = getting warmer).</summary>
    int ProgressionDelta,
    IReadOnlyList<Guid> FamilyMemberIds,
    int FamilySize,
    string? Summary,
    DateTimeOffset At,
    string? Error = null);
