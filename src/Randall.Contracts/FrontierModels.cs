namespace Randall.Contracts;

/// <summary>
/// Ranked unexplored CFG branches and session forks (gray doors) for stalk campaigns.
/// Persisted at <c>data/stalk/&lt;project&gt;/frontier.json</c>.
/// </summary>
public sealed record FrontierReportDto(
    string Project,
    string ScoredAt,
    /// <summary>cfg | session | mixed | empty</summary>
    string Mode,
    string Summary,
    int CoverageBlockCount,
    int FrontierCount,
    string? AnalysisPath,
    IReadOnlyList<FrontierBranchDto> Frontiers,
    string WorkflowHint);

/// <summary>
/// One scored gray door: covered predecessor → unexplored successor, or session fork.
/// </summary>
public sealed record FrontierBranchDto(
    string EdgeKey,
    /// <summary>cfg-branch | session-fork | edge-gap</summary>
    string Kind,
    int Score,
    double CfgDistance,
    double Rarity,
    int UnseenSuccessorCount,
    double SinkProximity,
    string? FunctionName,
    string? FromAddress,
    string ToAddress,
    string? Module,
    string Detail,
    /// <summary>Layer hits on covered predecessor(s) — "almost opened" signal.</summary>
    int ApproachCount = 0,
    /// <summary>Layer hits on the unexplored successor — 0 means still unopened.</summary>
    int CrossedCount = 0);
