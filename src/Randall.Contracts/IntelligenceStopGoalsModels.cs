namespace Randall.Contracts;

/// <summary>
/// Intelligence-driven fuzz/campaign stop goals — stop or mark complete when scream thresholds are met.
/// Configure on <c>fuzz.stopGoals</c> (project YAML) or <c>stopGoals</c> (campaign YAML / run override).
/// Legacy <c>fuzz.screamScoreGoal</c> maps to <see cref="LegacyScreamScoreGoal"/>.
/// </summary>
public sealed class IntelligenceStopGoalsConfig
{
    /// <summary>
    /// Stop when max project scream score or hot/purple scream count reaches this threshold.
    /// 0 = disabled. Mirrors legacy <c>fuzz.screamScoreGoal</c>.
    /// </summary>
    public int LegacyScreamScoreGoal { get; set; }

    /// <summary>Stop when N unique scream clusters each have ScreamScore ≥ MinScore.</summary>
    public UniqueScreamScoreGoal? UniqueScreamsWithScore { get; set; }

    /// <summary>Stop when N unique evolution families each have momentum ≥ MinMomentum.</summary>
    public UniqueScreamMomentumGoal? UniqueScreamsWithMomentum { get; set; }

    /// <summary>When a stop goal is met, enqueue top clusters for replay/minimize via hypothesis queue.</summary>
    public bool QueueTopClustersOnGoal { get; set; }

    public bool IsEnabled =>
        LegacyScreamScoreGoal > 0
        || UniqueScreamsWithScore is { Count: > 0, MinScore: > 0 }
        || UniqueScreamsWithMomentum is { Count: > 0, MinMomentum: > 0 };
}

public sealed class UniqueScreamScoreGoal
{
    public int Count { get; set; }
    public int MinScore { get; set; }
}

public sealed class UniqueScreamMomentumGoal
{
    public int Count { get; set; }
    public int MinMomentum { get; set; }
}

/// <summary>Evaluation snapshot for logs, API status, and UI progress chips.</summary>
public sealed record IntelligenceStopGoalProgressDto(
    bool Met,
    string? Reason,
    IReadOnlyDictionary<string, int> Counters);
