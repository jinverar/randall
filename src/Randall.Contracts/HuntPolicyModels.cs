namespace Randall.Contracts;

/// <summary>
/// How Randall spends the next execution budget — lineage breeding vs havoc vs Joker chaos.
/// Phase B Hunt Policy (see docs/HUNT_POLICY.md).
/// </summary>
public enum HuntExecutionMode
{
    Baseline,
    LineageBreed,
    HavocExplore,
    JokerInvoke,
}

public enum HuntPolicyActionKind
{
    Boost,
    Reduce,
    Deprioritize,
    Hold,
}

public sealed record HuntPolicyAction(
    HuntPolicyActionKind Kind,
    string Target,
    string Reason);

public sealed record HuntPolicyTermWeights(
    double Scream = 1.0,
    double Gravity = 1.0,
    double Frontier = 1.0,
    double Static = 1.0,
    double Oracle = 1.0,
    double Mutator = 1.0)
{
    public const double Min = 0.5;
    public const double Max = 2.0;
    public const double AdaptStep = 0.05;

    public HuntPolicyTermWeights Clamp() => new(
        Math.Clamp(Scream, Min, Max),
        Math.Clamp(Gravity, Min, Max),
        Math.Clamp(Frontier, Min, Max),
        Math.Clamp(Static, Min, Max),
        Math.Clamp(Oracle, Min, Max),
        Math.Clamp(Mutator, Min, Max));

    public double ForCategory(string category) => category switch
    {
        "scream" => Scream,
        "gravity" => Gravity,
        "frontier" => Frontier,
        "static" or "patch" => Static,
        "oracle" => Oracle,
        "mutator" => Mutator,
        _ => 1.0,
    };
}

public sealed record HuntPolicyFeedbackWindow(
    int StartIteration,
    int EndIteration,
    double PredictedScream,
    double PredictedGravity,
    double PredictedFrontier,
    double PredictedStatic,
    double PredictedOracle,
    double PredictedMutator,
    int ObservedNewEdges,
    int ObservedUniqueCrashes);

public sealed record HuntPolicyWeightsDto(
    string Project,
    int LastAdaptIteration,
    HuntPolicyTermWeights Weights,
    HuntPolicyFeedbackWindow? PendingWindow = null,
    IReadOnlyList<HuntPolicyFeedbackWindow>? RecentWindows = null);

public sealed record HuntPolicyDecision(
    int HuntValue,
    HuntExecutionMode Mode,
    string Summary,
    double JokerInvokeChance,
    bool NeedsExperiment,
    string? ExperimentHint,
    IReadOnlyList<OracleScoreTerm> Terms,
    string? FocusKind,
    string? FocusLabel,
    int FocusScore,
    string? PreferredMutator,
    IReadOnlyList<string>? LineageChain = null,
    string? TopHypothesisId = null,
    int TopHypothesisConfidence = 0,
    string? TopHypothesisStatement = null,
    IReadOnlyList<HuntPolicyAction>? Actions = null,
    HuntPolicyTermWeights? AppliedWeights = null,
    HuntExecutionMode? RawMode = null)
{
    public static HuntPolicyDecision Inactive(string reason = "Hunt policy idle — no signals") =>
        new(0, HuntExecutionMode.Baseline, reason, 0, false, null, [], null, null, 0, null);
}

public sealed record HuntPolicySnapshotDto(
    string Project,
    int Iteration,
    DateTimeOffset At,
    HuntPolicyDecision Policy,
    ScreamEvolutionTelemetryDto? ScreamEvolution = null);
