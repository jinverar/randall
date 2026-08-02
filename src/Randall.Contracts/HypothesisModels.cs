using System.Text.Json.Serialization;

namespace Randall.Contracts;

/// <summary>
/// Lifecycle of a research hypothesis — no exploit payloads.
/// v2 adds Supported/Weakened/Blocked/Invalidated; Pending/Running/Partial remain for legacy JSON.
/// </summary>
public enum HypothesisStatus
{
    /// <summary>Legacy synonym of <see cref="Proposed"/>.</summary>
    Pending,
    /// <summary>Legacy synonym of <see cref="Testing"/>.</summary>
    Running,
    Proposed,
    Testing,
    /// <summary>Evidence supports the claim but confirmation predicate not met.</summary>
    Supported,
    /// <summary>Negative evidence weakened the claim (e.g. flaky non-repro).</summary>
    Weakened,
    /// <summary>Legacy mid-state; prefer Supported/Weakened.</summary>
    Partial,
    Inconclusive,
    Refuted,
    Confirmed,
    /// <summary>Cannot evaluate — missing primary fault / rejected artifacts.</summary>
    Blocked,
    /// <summary>Backing evidence invalidated after generation.</summary>
    Invalidated,
    /// <summary>Loaded from schemaVersion 1; do not treat as v2 Confirmed.</summary>
    LegacyUnverified,
}

/// <summary>Support strength grade — not a probability.</summary>
public enum HypothesisSupportGrade
{
    Unsupported,
    Weak,
    Moderate,
    Strong,
    Confirmed,
}

/// <summary>Typed hypothesis class (P1) — drives registry + predicate evaluation.</summary>
public enum HypothesisKind
{
    Unknown,
    TriggerSensitivity,
    ReplaySamePrimaryFault,
    MutatorCorrelation,
    InputRegionInfluence,
    DestinationControl,
    WrittenValueControl,
    RootCause,
    FamilyProgression,
    SharedCodeTwin,
}

/// <summary>Machine-readable confirmation predicate — evaluator logic; human text is derived.</summary>
public enum HypothesisPredicateKind
{
    /// <summary>Any abnormal exit / crash observed (never alone confirms typed hyps).</summary>
    AbnormalExitReproduced,
    /// <summary>Same primary-fault identity as baseline (module/offset/access/family).</summary>
    SamePrimaryFault,
    /// <summary>Safe-adjacent flip clears or relocates fault — TriggerSensitivity only.</summary>
    TriggerSensitiveRegion,
    /// <summary>Campaign mutator correlation with min sample sizes.</summary>
    MutatorCorrelationCampaign,
    /// <summary>Family progression step / momentum advanced vs baseline.</summary>
    FamilyProgressionAdvanced,
    /// <summary>Controlled destination / written-value claim (capability hyps).</summary>
    CapabilityControl,
    /// <summary>Generic observation match (legacy expectedObservation text — not used for Confirm).</summary>
    LegacyObservationText,
}

/// <summary>Deterministic experiment kinds queued by the Hypothesis Engine (Phase C).</summary>
public enum HypothesisExperimentKind
{
    /// <summary>Replay crash input through a held mutator from lineage.</summary>
    HoldMutator,
    /// <summary>Bit/byte sweep around pattern-depth offset (±range).</summary>
    SweepOffset,
    /// <summary>Re-run mutator chain from seed (replay/minimize style).</summary>
    ReplayLineage,
    /// <summary>Probe boundary/interesting values at suspected field.</summary>
    BoundaryProbe,
    /// <summary>Shrink input while preserving bytes at suspected offset.</summary>
    MinimizeHold,
    /// <summary>Counterfactual safe-adjacent / still-corrupt probes (TriggerSensitivity only).</summary>
    CounterfactualSafeAdjacent,
}

/// <summary>Suggested deterministic experiment — research sweeps/holds only.</summary>
public sealed record HypothesisExperimentDto(
    HypothesisExperimentKind Kind,
    string Description,
    string? Mutator = null,
    int? OffsetBytes = null,
    int? SweepRange = null,
    IReadOnlyList<string>? MutatorChain = null,
    string? Command = null,
    /// <summary>Small execution budget per hypothesis (default 3 iterations).</summary>
    int BudgetIterations = 3);

/// <summary>Primary-fault identity snapshot for experiment comparison (v2).</summary>
public sealed record FaultIdentitySnapshot(
    int? ExitCode = null,
    string? CrashClass = null,
    string? FaultModule = null,
    string? FaultOffset = null,
    string? AccessKind = null,
    string? FaultAddressClass = null,
    string? FamilyId = null,
    string? StackFingerprint = null,
    string? FaultingFunction = null,
    bool IsTeardownOnly = false,
    bool HasVerifiedPrimaryFault = false);

/// <summary>Structured comparison of baseline vs experiment fault identity.</summary>
public sealed record FaultComparison(
    bool ExitMatches,
    bool ModuleMatches,
    bool OffsetMatches,
    bool AccessMatches,
    bool StackMatches,
    bool FamilyMatches,
    bool PrimaryFaultMatches,
    string Summary);

/// <summary>Machine-readable expected predicate for confirmation (v2).</summary>
public sealed record ExpectedPredicate(
    HypothesisPredicateKind Kind,
    FaultIdentitySnapshot? BaselineFault = null,
    int? MinMomentum = null,
    int? MinExecutions = null,
    int? MinCrashes = null,
    string? Mutator = null,
    string? FamilyId = null,
    string? RegionLabel = null,
    string? HumanSummary = null);

/// <summary>Reference to an <see cref="EvidenceFact"/> by stable name (not free-form tags).</summary>
public sealed record HypothesisEvidenceRef(
    string FactId,
    string? SourceArtifact = null,
    bool Invalidated = false);

/// <summary>Structured experiment outcome with optional fault comparison (v2).</summary>
public sealed record ExperimentResult(
    HypothesisStatus Status,
    int SupportScoreAfter,
    string? Observation,
    int? Iteration,
    DateTimeOffset At,
    int? SupportScoreBefore = null,
    FaultComparison? FaultComparison = null,
    FaultIdentitySnapshot? ObservedFault = null,
    IReadOnlyList<string>? SupportReasons = null,
    IReadOnlyList<string>? SupportDeltas = null);

/// <summary>
/// Outcome after an experiment runs — updates hypothesis support score.
/// Legacy shape kept for JSON; prefer <see cref="ExperimentResult"/> fields when present.
/// </summary>
public sealed record HypothesisResultDto(
    HypothesisStatus Status,
    [property: JsonPropertyName("confidenceAfter")]
    int ConfidenceAfter,
    string? Observation,
    int? Iteration,
    DateTimeOffset At,
    [property: JsonPropertyName("confidenceBefore")]
    int? ConfidenceBefore = null,
    FaultComparison? FaultComparison = null,
    FaultIdentitySnapshot? ObservedFault = null,
    IReadOnlyList<string>? SupportReasons = null,
    IReadOnlyList<string>? SupportDeltas = null)
{
    [JsonIgnore]
    public int SupportScoreAfter => ConfidenceAfter;

    [JsonIgnore]
    public int? SupportScoreBefore => ConfidenceBefore;

    public ExperimentResult ToExperimentResult() => new(
        Status, ConfidenceAfter, Observation, Iteration, At, ConfidenceBefore,
        FaultComparison, ObservedFault, SupportReasons, SupportDeltas);

    public static HypothesisResultDto FromExperimentResult(ExperimentResult r) => new(
        r.Status, r.SupportScoreAfter, r.Observation, r.Iteration, r.At, r.SupportScoreBefore,
        r.FaultComparison, r.ObservedFault, r.SupportReasons, r.SupportDeltas);
}

/// <summary>One testable hypothesis derived from crash intelligence evidence.</summary>
public sealed record HypothesisDto(
    /// <summary>
    /// Unique instance id (v2: Guid "N"). Legacy v1 reused type strings — migrated on read.
    /// </summary>
    string Id,
    Guid? CrashId,
    string Statement,
    /// <summary>Support score 0–100 (not a calibrated probability). JSON: confidencePercent for compat.</summary>
    [property: JsonPropertyName("confidencePercent")]
    int ConfidencePercent,
    HypothesisExperimentDto Experiment,
    string ExpectedObservation,
    HypothesisStatus Status,
    HypothesisResultDto? Result = null,
    /// <summary>Legacy free-form evidence tags; prefer <see cref="EvidenceRefs"/>.</summary>
    IReadOnlyList<string>? Evidence = null,
    /// <summary>Stable type id e.g. hyp-oracle-correlate — never used as unique instance id.</summary>
    string? TypeId = null,
    HypothesisKind Kind = HypothesisKind.Unknown,
    ExpectedPredicate? ExpectedPredicate = null,
    IReadOnlyList<HypothesisEvidenceRef>? EvidenceRefs = null,
    HypothesisSupportGrade SupportGrade = HypothesisSupportGrade.Unsupported,
    IReadOnlyList<string>? SupportReasons = null,
    bool LegacyUnverified = false,
    FaultIdentitySnapshot? BaselineFault = null)
{
    /// <summary>Alias for UI/API — same value as <see cref="ConfidencePercent"/>.</summary>
    [JsonPropertyName("supportScore")]
    public int SupportScore => ConfidencePercent;

    /// <summary>Hypothesis type id (falls back to Id for pre-migration rows).</summary>
    [JsonIgnore]
    public string HypothesisTypeId =>
        !string.IsNullOrWhiteSpace(TypeId) ? TypeId! : Id;

    /// <summary>Instance id — Guid when migrated; otherwise Id string.</summary>
    [JsonIgnore]
    public string HypothesisInstanceId => Id;

    public bool IsOpen => Status is HypothesisStatus.Pending or HypothesisStatus.Proposed
        or HypothesisStatus.Running or HypothesisStatus.Testing
        or HypothesisStatus.Supported or HypothesisStatus.Weakened
        or HypothesisStatus.Partial or HypothesisStatus.Inconclusive;

    public bool IsTerminal => Status is HypothesisStatus.Confirmed or HypothesisStatus.Refuted
        or HypothesisStatus.Blocked or HypothesisStatus.Invalidated
        or HypothesisStatus.LegacyUnverified;
}

/// <summary>Ranked hypotheses for one crash — persisted under <c>_hypotheses/{guid}.json</c>.</summary>
public sealed record HypothesisSetDto(
    bool Ok,
    Guid CrashId,
    string Project,
    IReadOnlyList<HypothesisDto> Hypotheses,
    DateTimeOffset At,
    string? Error = null,
    /// <summary>JSON schema version — v1 legacy; v2 splits instance/type ids + predicates.</summary>
    int SchemaVersion = 1,
    /// <summary>Artifact / primary-fault prerequisites for this set.</summary>
    HypothesisArtifactManifest? Manifest = null);

/// <summary>Prerequisites for hypothesis generation / promotion.</summary>
public sealed record HypothesisArtifactManifest(
    bool HasVerifiedPrimaryFault = false,
    bool DebuggerArtifactsPresent = false,
    bool IdentityRejected = false,
    bool TeardownOnly = false,
    bool IncompleteArtifacts = false,
    string? BlockReason = null,
    IReadOnlyList<string>? AvailableCapabilities = null);

/// <summary>Queued experiment awaiting fuzz-loop execution budget.</summary>
public sealed record HypothesisQueueEntryDto(
    string HypothesisId,
    Guid CrashId,
    string Project,
    HypothesisExperimentDto Experiment,
    [property: JsonPropertyName("confidencePercent")]
    int ConfidencePercent,
    int RemainingBudget,
    int SweepIndex,
    DateTimeOffset QueuedAt,
    string? TypeId = null)
{
    [JsonPropertyName("supportScore")]
    public int SupportScore => ConfidencePercent;
}

/// <summary>Project-level hypothesis queue + top pick — <c>hypothesis_queue.json</c>.</summary>
public sealed record HypothesisProjectSnapshotDto(
    string Project,
    int Iteration,
    DateTimeOffset At,
    IReadOnlyList<HypothesisQueueEntryDto> Queue,
    HypothesisDto? TopHypothesis);

/// <summary>One row in the project hypothesis ledger (<c>_hypotheses/ledger.json</c>).</summary>
public sealed record HypothesisLedgerEntryDto(
    string HypothesisId,
    Guid CrashId,
    string Statement,
    [property: JsonPropertyName("confidencePercent")]
    int ConfidencePercent,
    HypothesisStatus Status,
    HypothesisExperimentKind ExperimentKind,
    HypothesisResultDto? Result,
    DateTimeOffset At,
    string? TypeId = null,
    HypothesisKind Kind = HypothesisKind.Unknown,
    HypothesisSupportGrade SupportGrade = HypothesisSupportGrade.Unsupported)
{
    [JsonPropertyName("supportScore")]
    public int SupportScore => ConfidencePercent;
}

/// <summary>Project-level hypothesis ledger — aggregated view for Investigation and Hunt Policy.</summary>
public sealed record HypothesisProjectLedgerDto(
    string Project,
    int Iteration,
    DateTimeOffset At,
    IReadOnlyList<HypothesisLedgerEntryDto> Entries,
    HypothesisDto? TopPending,
    HypothesisProjectSnapshotDto? Queue = null);
