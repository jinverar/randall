namespace Randall.Contracts;

/// <summary>
/// Study checklist item inside an RF research package (teaching rollup).
/// </summary>
public sealed record ResearchPackageItemDto(
    string Id,
    string Title,
    string Description,
    /// <summary>Suggested study order (1 = first).</summary>
    int Priority,
    IReadOnlyList<string> EvidenceRefs);

/// <summary>One experiment outcome summarized in the research package.</summary>
public sealed record ResearchPackageExperimentDto(
    string Id,
    string Kind,
    string Description,
    string Outcome,
    string? Detail = null);

/// <summary>
/// RF-#### style research package — teaching report for one crash finding.
/// Research-only; never includes exploit payloads, ROP, or shellcode.
/// Persisted as <c>{guid}_research_package.json</c>.
/// </summary>
public sealed record ResearchPackageReportDto(
    bool Ok,
    string Project,
    Guid? CrashId,
    /// <summary>Stable report id, e.g. <c>RF-A1B2C3D4</c>.</summary>
    string ReportId,
    string Summary,
    /// <summary>Target executable / harness name when known.</summary>
    string? Target,
    /// <summary>Target version / build stamp when known.</summary>
    string? TargetVersion,
    /// <summary>How the crash was discovered (mutator, iteration, run id).</summary>
    string? Discovery,
    /// <summary>Mutation ancestry / lineage summary.</summary>
    string? MutationAncestry,
    /// <summary>Minimal repro notes (input hash/path, size).</summary>
    string? MinimalRepro,
    /// <summary>Debugger observation summary (access/class/influence).</summary>
    string? DebuggerEvidence,
    /// <summary>Root-cause category + educational summary.</summary>
    string? RootCause,
    /// <summary>Influence map rollup.</summary>
    string? Influence,
    /// <summary>Primitive maturity + top capabilities.</summary>
    string? Primitive,
    /// <summary>Mitigation posture notes (teaching — not patch apply).</summary>
    string? Mitigations,
    /// <summary>Experiments run (counterfactual / hypothesis / skeptic).</summary>
    IReadOnlyList<ResearchPackageExperimentDto> Experiments,
    /// <summary>Claims/hypotheses confirmed by evidence.</summary>
    IReadOnlyList<string> Confirmed,
    /// <summary>Claims/hypotheses disproven or falsified.</summary>
    IReadOnlyList<string> Disproven,
    /// <summary>Research maturity label, e.g. R4 · Primitive candidate.</summary>
    string? Maturity,
    /// <summary>Open questions for the researcher.</summary>
    IReadOnlyList<string> OpenQuestions,
    /// <summary>Conceptual remediation suggestions — never auto-applied patches.</summary>
    string? SuggestedRemediation,
    /// <summary>Legacy/study checklist packages (advisor + ethics).</summary>
    IReadOnlyList<ResearchPackageItemDto> Packages,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN</summary>
    string Confidence,
    DateTimeOffset At,
    string? Error = null,
    /// <summary>JSON schema version for persisted research artifacts (v1).</summary>
    int SchemaVersion = 1);
