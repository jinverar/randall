namespace Randall.Contracts;

/// <summary>How a failure was observed — crash canister or silent oracle finding.</summary>
public enum GenealogyFailureKind
{
    Crash,
    SilentFinding,
}

/// <summary>One crash or silent finding participating in a genealogy lineage.</summary>
public sealed record GenealogyMemberDto(
    Guid CrashId,
    GenealogyFailureKind Kind,
    string? ClusterKey,
    string? FamilyId,
    string? FaultingFunction,
    RootCauseCategory? Category,
    string? PatternHint,
    string? TriageTag);

/// <summary>
/// One probable vulnerability lineage — crashes/silent findings sharing root cause,
/// faulting function, and/or pattern family. Teaching rollup only.
/// </summary>
public sealed record GenealogyLineageDto(
    string LineageId,
    string Label,
    RootCauseCategory Category,
    string? FaultingFunction,
    string? PatternFamily,
    int FailureCount,
    IReadOnlyList<GenealogyMemberDto> Members,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN</summary>
    string Confidence,
    string EducationalNote);

/// <summary>
/// Project-level bug genealogy — groups failures into N probable vulns / M failures.
/// Persisted as <c>data/crashes/&lt;project&gt;/bug_genealogy.json</c>.
/// </summary>
public sealed record BugGenealogyReportDto(
    bool Ok,
    string Project,
    /// <summary>Distinct probable vulnerability lineages (N).</summary>
    int ProbableVulnCount,
    /// <summary>Total crash + silent finding members (M).</summary>
    int FailureCount,
    string Summary,
    IReadOnlyList<GenealogyLineageDto> Lineages,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN</summary>
    string Confidence,
    DateTimeOffset At,
    string? Error = null);
