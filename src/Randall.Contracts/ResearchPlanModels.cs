namespace Randall.Contracts;

/// <summary>
/// Origin of a research claim — which intelligence layer asserted it.
/// Research-only taxonomy; no exploit automation.
/// </summary>
public enum ResearchClaimKind
{
    /// <summary>A root-cause category assertion (bounds/lifetime/size/…).</summary>
    RootCause,
    /// <summary>An input-region → program-state influence assertion.</summary>
    InputInfluence,
    /// <summary>A control-primitive assertion derived from confirmed influence (research-only).</summary>
    Primitive,
    /// <summary>A mutator-lineage causality assertion.</summary>
    Lineage,
    /// <summary>An oracle-signal correlation assertion.</summary>
    Oracle,
}

/// <summary>
/// One falsifiable assertion pulled from the crash-intelligence layers. The Research Planner
/// turns each claim into an ordered experiment (hypothesis → experiment → expected observation).
/// </summary>
public sealed record ResearchClaimDto(
    string Id,
    ResearchClaimKind Kind,
    /// <summary>Plain-language, testable statement of the claim.</summary>
    string Statement,
    /// <summary>Normalized 0–100 confidence for ranking.</summary>
    int ConfidencePercent,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN rollup label.</summary>
    string ConfidenceLabel,
    /// <summary>Whether a deterministic experiment has already confirmed this claim.</summary>
    bool Confirmed,
    /// <summary>Evidence-fact names / refs that back this claim.</summary>
    IReadOnlyList<string> EvidenceRefs,
    /// <summary>Source layer: root_cause / influence / hypothesis / oracle.</summary>
    string Source,
    /// <summary>Byte offset in the crash input this claim is about, when applicable.</summary>
    int? OffsetBytes = null,
    /// <summary>Linked hypothesis id when the claim reuses an existing hypothesis.</summary>
    string? HypothesisId = null);

/// <summary>
/// One ordered step of a research plan — a claim, the experiment that tests it, and what
/// observation would support (or fail to support) it. Deterministic sweeps/holds only.
/// </summary>
public sealed record ResearchStepDto(
    /// <summary>1-based execution order.</summary>
    int Order,
    ResearchClaimDto Claim,
    HypothesisExperimentDto Experiment,
    string ExpectedObservation,
    /// <summary>Why this step is placed here (information gain / dependency).</summary>
    string Rationale,
    /// <summary>True when this step is a skeptic falsification gate rather than a confirmation.</summary>
    bool SkepticGate = false,
    string? HypothesisId = null);

/// <summary>
/// Ordered research plan for one crash — hypotheses → experiments → expected observations.
/// Persisted as <c>{guid}_research_plan.json</c>. Research/teaching only, no exploit payloads.
/// </summary>
public sealed record ResearchPlanDto(
    bool Ok,
    Guid CrashId,
    string Project,
    /// <summary>One-line research objective for the operator.</summary>
    string Objective,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN rollup across claims.</summary>
    string Confidence,
    IReadOnlyList<ResearchStepDto> Steps,
    IReadOnlyList<ResearchClaimDto> Claims,
    DateTimeOffset At,
    /// <summary>Plain-language teaching summary for the Investigation UI.</summary>
    string? Summary = null,
    string? Error = null,
    /// <summary>JSON schema version for persisted research artifacts (v1). Absent on legacy files → default 1.</summary>
    int SchemaVersion = 1);
