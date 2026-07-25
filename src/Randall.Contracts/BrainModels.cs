namespace Randall.Contracts;

/// <summary>
/// Closed-loop hunt decision — fuses frontier, static map, oracle, mutator credit, and scream novelty.
/// Persisted under <c>data/stalk/&lt;project&gt;/brain_last.json</c> and surfaced on Scare Floor.
/// </summary>
public sealed record NextHuntDecision(
    int Iteration,
    DateTimeOffset At,
    string Project,
    /// <summary>False when brain is disabled or no stalk/scream signals exist.</summary>
    bool Active,
    string Summary,
    /// <summary>frontier | static | oracle | scream | mutator | baseline</summary>
    string FocusKind,
    string? FocusLabel,
    int FocusScore,
    /// <summary>Brain-preferred mutator when confidence is high; null keeps credit roulette.</summary>
    string? PreferredMutator,
    /// <summary>Probability [0.5–0.9] of picking priority corpus over YAML seeds.</summary>
    double CorpusPriorityBias,
    /// <summary>Soft extra corpus energy after interesting iterations (0–8).</summary>
    int RecommendedEnergyBoost,
    IReadOnlyList<OracleScoreTerm> WhyTerms,
    OracleScore ScoreBreakdown)
{
    public static NextHuntDecision Inactive(string project, int iteration = 0) =>
        new(
            iteration,
            DateTimeOffset.UtcNow,
            project,
            false,
            "Brain idle — no frontier, static map, oracle, or scream signals yet.",
            "baseline",
            null,
            0,
            null,
            0.65,
            0,
            [],
            OracleScore.Empty);
}

/// <summary>API payload for live or persisted brain state.</summary>
public sealed record BrainDecisionSnapshotDto(
    string Project,
    bool Enabled,
    bool HasSignals,
    NextHuntDecision? LastDecision,
    DateTimeOffset? PersistedAt,
    string? EmptyHint = null);
