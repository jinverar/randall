namespace Randall.Contracts;

/// <summary>
/// How Randall spends the next execution budget — lineage breeding vs havoc vs Joker chaos.
/// Phase B Hunt Policy (see docs/ROADMAP_INTELLIGENCE.md).
/// </summary>
public enum HuntExecutionMode
{
    /// <summary>Default mutator credit / brain focus steering.</summary>
    Baseline,
    /// <summary>Bias mutator chains on warming scream families (Phase A momentum).</summary>
    LineageBreed,
    /// <summary>Push havoc / frontier exploration when static gaps dominate.</summary>
    HavocExplore,
    /// <summary>Brain raises Joker invoke chance — Joker stays dumb, only timing changes.</summary>
    JokerInvoke,
}

/// <summary>
/// Consolidated hunt-value decision — fuses coverage, static, oracle, scream momentum,
/// mutator credit, frontier distance, debugger influence minus cost and duplicate penalties.
/// </summary>
public sealed record HuntPolicyDecision(
    int HuntValue,
    HuntExecutionMode Mode,
    string Summary,
    /// <summary>Effective Joker invoke probability [0–1] for this iteration (timing only).</summary>
    double JokerInvokeChance,
    /// <summary>Phase C stub — corruption chain suggests live experiment / TTD rewind.</summary>
    bool NeedsExperiment,
    string? ExperimentHint,
    IReadOnlyList<OracleScoreTerm> Terms,
    string? FocusKind,
    string? FocusLabel,
    int FocusScore,
    string? PreferredMutator,
    /// <summary>Lineage chain to breed when <see cref="Mode"/> is <see cref="HuntExecutionMode.LineageBreed"/>.</summary>
    IReadOnlyList<string>? LineageChain = null,
    /// <summary>Phase C — top pending hypothesis id when <see cref="NeedsExperiment"/> is set.</summary>
    string? TopHypothesisId = null,
    int TopHypothesisConfidence = 0,
    string? TopHypothesisStatement = null)
{
    public static HuntPolicyDecision Inactive(string reason = "Hunt policy idle — no signals") =>
        new(0, HuntExecutionMode.Baseline, reason, 0, false, null, [], null, null, 0, null);
}

/// <summary>Persisted hunt policy snapshot under <c>data/stalk/&lt;project&gt;/hunt_policy_last.json</c>.</summary>
public sealed record HuntPolicySnapshotDto(
    string Project,
    int Iteration,
    DateTimeOffset At,
    HuntPolicyDecision Policy,
    ScreamEvolutionTelemetryDto? ScreamEvolution = null);
