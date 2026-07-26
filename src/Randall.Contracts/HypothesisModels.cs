namespace Randall.Contracts;

/// <summary>Lifecycle of a research hypothesis — no exploit payloads.</summary>
public enum HypothesisStatus
{
    Pending,
    Running,
    Confirmed,
    Partial,
    Refuted,
    Inconclusive,
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

/// <summary>Outcome after an experiment runs — updates hypothesis confidence.</summary>
public sealed record HypothesisResultDto(
    HypothesisStatus Status,
    int ConfidenceAfter,
    string? Observation,
    int? Iteration,
    DateTimeOffset At);

/// <summary>One testable hypothesis derived from crash intelligence evidence.</summary>
public sealed record HypothesisDto(
    string Id,
    Guid? CrashId,
    string Statement,
    int ConfidencePercent,
    HypothesisExperimentDto Experiment,
    string ExpectedObservation,
    HypothesisStatus Status,
    HypothesisResultDto? Result = null,
    IReadOnlyList<string>? Evidence = null);

/// <summary>Ranked hypotheses for one crash — persisted as <c>{guid}_hypotheses.json</c>.</summary>
public sealed record HypothesisSetDto(
    bool Ok,
    Guid CrashId,
    string Project,
    IReadOnlyList<HypothesisDto> Hypotheses,
    DateTimeOffset At,
    string? Error = null);

/// <summary>Queued experiment awaiting fuzz-loop execution budget.</summary>
public sealed record HypothesisQueueEntryDto(
    string HypothesisId,
    Guid CrashId,
    string Project,
    HypothesisExperimentDto Experiment,
    int ConfidencePercent,
    int RemainingBudget,
    int SweepIndex,
    DateTimeOffset QueuedAt);

/// <summary>Project-level hypothesis queue + top pick — <c>hypothesis_queue.json</c>.</summary>
public sealed record HypothesisProjectSnapshotDto(
    string Project,
    int Iteration,
    DateTimeOffset At,
    IReadOnlyList<HypothesisQueueEntryDto> Queue,
    HypothesisDto? TopHypothesis);
