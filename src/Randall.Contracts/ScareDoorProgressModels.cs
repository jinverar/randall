namespace Randall.Contracts;

/// <summary>
/// Per Scare Door hunt pressure ledger — persisted at <c>data/stalk/&lt;project&gt;/scare_door_progress.json</c>.
/// </summary>
public sealed record ScareDoorBranchProgressDto(
    string EdgeKey,
    int Attempts = 0,
    double ClosestDistance = 0,
    string? LastProgress = null,
    string? BestSeedId = null,
    string? BestMutation = null,
    int StaticScore = 0,
    double ProgressFraction = 0,
    int InitialCfgDistance = 0,
    int BestEdgeGain = 0,
    int LastIteration = 0,
    DateTimeOffset? UpdatedAt = null);

public sealed record ScareDoorProgressReportDto(
    string Project,
    DateTimeOffset UpdatedAt,
    string? PinnedEdgeKey,
    IReadOnlyDictionary<string, ScareDoorBranchProgressDto> Doors);
