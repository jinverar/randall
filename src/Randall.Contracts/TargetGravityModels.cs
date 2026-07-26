namespace Randall.Contracts;

/// <summary>
/// Reachability pressure toward interesting sinks — risk × unexploredness / distance from covered BBs.
/// Persisted at <c>data/stalk/&lt;project&gt;/target_gravity.json</c>.
/// Complements <see cref="FrontierReportDto"/> (gray doors) without replacing hunt policy signals.
/// </summary>
public sealed record TargetGravityReportDto(
    string Project,
    string ScoredAt,
    /// <summary>cfg | surface | oracle | mixed | empty</summary>
    string Mode,
    string Summary,
    int CoverageBlockCount,
    int WellCount,
    /// <summary>Normalized aggregate of top wells (0–100).</summary>
    int AggregatePressure,
    IReadOnlyList<TargetGravityWellDto> Wells,
    string WorkflowHint,
    /// <summary>Last persisted top-N wells with human-readable pull reasons (for brain / UI).</summary>
    IReadOnlyList<TargetGravityTopSnapshotDto> TopSnapshots);

/// <summary>Compact top-well snapshot for persistence and brain quality filtering.</summary>
public sealed record TargetGravityTopSnapshotDto(
    string Key,
    int Score,
    string Label,
    string Reason);

/// <summary>
/// One scored sink or unexplored block under reachability pressure toward a dangerous surface.
/// </summary>
public sealed record TargetGravityWellDto(
    string Key,
    /// <summary>sink-call | alloc | ghidra-dangerous | oracle-near-miss | missed-surface</summary>
    string Kind,
    int GravityScore,
    double Risk,
    double Unexploredness,
    int Distance,
    string? FunctionName,
    string? Address,
    string? SinkSymbol,
    string Detail);
