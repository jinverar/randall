namespace Randall.Contracts;

/// <summary>Outcome of one counterfactual probe relative to the original crash.</summary>
public enum CounterfactualOutcome
{
    /// <summary>Probe not yet executed against a target.</summary>
    Pending,
    /// <summary>Still crashes — adjacent corrupt.</summary>
    StillCorrupt,
    /// <summary>Crash disappears — adjacent safe.</summary>
    SafeAdjacent,
    /// <summary>Execution inconclusive (timeout / harness error).</summary>
    Inconclusive,
}

/// <summary>One nearby input change derived from HypothesisEngine sweep/boundary patterns.</summary>
public sealed record CounterfactualProbeDto(
    string Id,
    HypothesisExperimentKind Kind,
    int SweepIndex,
    int OffsetBytes,
    /// <summary>Hamming distance in bytes vs original (approx for bitflips).</summary>
    int ByteDelta,
    string Description,
    CounterfactualOutcome Outcome,
    string? Detail = null);

/// <summary>
/// Counterfactual fuzzing report — smallest nearby change that makes the bug disappear,
/// plus adjacent safe vs corrupt boundary map. Research/teaching only; no exploit payloads.
/// Persisted as <c>{guid}_counterfactual.json</c>.
/// </summary>
public sealed record CounterfactualReportDto(
    bool Ok,
    Guid CrashId,
    string Project,
    int? SuspectedOffset,
    string Summary,
    /// <summary>Smallest byte-delta probe that yielded SafeAdjacent, when known.</summary>
    CounterfactualProbeDto? SmallestSafeChange,
    IReadOnlyList<CounterfactualProbeDto> Probes,
    int SafeAdjacentCount,
    int StillCorruptCount,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN</summary>
    string Confidence,
    DateTimeOffset At,
    string? Error = null,
    /// <summary>True when probes were executed against a target/replay (not plan-only).</summary>
    bool LiveExecuted = false,
    /// <summary>Number of probes that were actually executed (bounded budget).</summary>
    int ExperimentsExecuted = 0,
    /// <summary>Hypothesis ids whose confidence/status were updated from live outcomes.</summary>
    IReadOnlyList<string>? UpdatedHypothesisIds = null,
    /// <summary>JSON schema version for persisted research artifacts (v1).</summary>
    int SchemaVersion = 1);

/// <summary>
/// Result of the counterfactual live execution loop: execute → observe → update → persist.
/// </summary>
public sealed record CounterfactualLiveResultDto(
    bool Ok,
    CounterfactualReportDto Report,
    HypothesisSetDto? Hypotheses,
    CrashInfluenceMapDto? Influence,
    SkepticReportDto? Skeptic,
    int ExperimentsExecuted,
    bool LiveExecuted,
    string Summary,
    DateTimeOffset At,
    string? Error = null);
