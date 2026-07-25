namespace Randall.Contracts;

/// <summary>
/// Reviewer-facing decision shape — "interesting therefore I will do X next."
/// Serialized as <c>decision</c> alongside <see cref="NextHuntDecision"/> on brain API payloads.
/// </summary>
public sealed record RandallDecisionActions(
    bool RetainFocus,
    double EnergyMultiplier,
    string? PreferredMutator,
    string? TargetFunction,
    double CorpusPriorityBias);

/// <summary>
/// Stable API alias for external docs — maps from <see cref="NextHuntDecision"/>.
/// </summary>
public sealed record RandallDecisionDto(
    string InputId,
    double Score,
    IReadOnlyDictionary<string, int> Reasons,
    RandallDecisionActions Actions,
    string Summary);

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
    /// <summary>Maps internal hunt fields to the reviewer <c>RandallDecision</c> contract.</summary>
    public RandallDecisionDto ToRandallDecision()
    {
        var inputId = string.IsNullOrWhiteSpace(FocusLabel)
            ? FocusKind
            : $"{FocusKind}:{FocusLabel}";
        var score = ScoreBreakdown.Total > 0 ? ScoreBreakdown.Total : FocusScore;
        var reasons = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var term in WhyTerms)
        {
            var key = MapReasonKey(term.Label);
            reasons[key] = reasons.TryGetValue(key, out var prev) ? prev + term.Points : term.Points;
        }

        if (reasons.Count == 0 && FocusScore > 0)
            reasons["huntPriority"] = FocusScore;

        var targetFunction = FocusKind is "static" or "patch" or "frontier" or "scream"
            ? FocusLabel
            : null;

        return new RandallDecisionDto(
            inputId,
            score,
            reasons,
            new RandallDecisionActions(
                RetainFocus: Active,
                EnergyMultiplier: RecommendedEnergyBoost > 0
                    ? Math.Round(1.0 + RecommendedEnergyBoost / 4.0, 2)
                    : 1.0,
                PreferredMutator,
                targetFunction,
                CorpusPriorityBias),
            Summary);
    }

    private static string MapReasonKey(string label)
    {
        var normalized = label.Trim().ToLowerInvariant();
        if (normalized.Contains("frontier"))
            return "frontierProximity";
        if (normalized.Contains("fuzz priority") || normalized.Contains("static map"))
            return "staticTargetPriority";
        if (normalized.Contains("coverage gap") || normalized.Contains("partial coverage") || normalized.Contains("new coverage"))
            return "newCoverage";
        if (normalized.Contains("oracle") || normalized.Contains("violation") || normalized.Contains("near miss"))
            return "oracleViolation";
        if (normalized.Contains("mutator") || normalized.Contains("productive edges"))
            return "mutationSuccess";
        if (normalized.Contains("scream") || normalized.Contains("novelty"))
            return "crashNovelty";
        if (normalized.Contains("change score") || normalized.Contains("priority delta"))
            return "patchDelta";
        if (normalized.Contains("saturation"))
            return "duplicatePenalty";
        return normalized.Replace(' ', '_');
    }

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
    string? EmptyHint = null,
    /// <summary>Reviewer <c>RandallDecision</c> alias — inputId, score, reasons, actions.</summary>
    RandallDecisionDto? Decision = null)
{
    public static BrainDecisionSnapshotDto FromDecision(
        NextHuntDecision? decision,
        string project,
        bool enabled = true,
        string? emptyHint = null) =>
        decision is null
            ? new BrainDecisionSnapshotDto(
                project,
                enabled,
                false,
                null,
                null,
                emptyHint,
                null)
            : new BrainDecisionSnapshotDto(
                project,
                enabled,
                decision.Active,
                decision,
                decision.At,
                emptyHint,
                decision.ToRandallDecision());
}
