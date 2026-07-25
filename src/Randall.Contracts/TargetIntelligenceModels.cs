namespace Randall.Contracts;

/// <summary>
/// Unified target profile aggregating static map, runtime, frontier, crash, and oracle stats.
/// Persisted at <c>data/stalk/&lt;project&gt;/target_intelligence.json</c>.
/// </summary>
public sealed record TargetIntelligenceDto(
    string Project,
    string UpdatedAt,
    string Summary,
    TargetIntelligenceStaticDto? Static,
    TargetIntelligenceDynamicDto? Dynamic,
    TargetIntelligenceFrontierDto? Frontier,
    TargetIntelligenceCrashDto? Crashes,
    TargetIntelligenceOracleDto? Oracles,
    IReadOnlyList<TargetIntelligenceCampaignDto> RecentCampaigns);

public sealed record TargetIntelligenceStaticDto(
    string? Binary,
    double? CoveragePercent,
    int FunctionCount,
    int ChangedFunctionCount,
    IReadOnlyList<TargetIntelligenceChangedFunctionDto> TopChangedFunctions);

public sealed record TargetIntelligenceChangedFunctionDto(
    string Name,
    string Address,
    string ChangeKind,
    double ChangeScore);

public sealed record TargetIntelligenceDynamicDto(
    int TotalIterations,
    int TotalCrashes,
    int UniqueClusters,
    int OracleFindingCount,
    string? LastRunId,
    DateTimeOffset? LastRunAt);

public sealed record TargetIntelligenceFrontierDto(
    int Count,
    string? Mode,
    string? TopTarget);

public sealed record TargetIntelligenceCrashDto(
    int Total,
    int UniqueClusters,
    IReadOnlyDictionary<string, int> MoodCounts,
    int MaxScreamScore);

public sealed record TargetIntelligenceOracleDto(
    int FindingCount,
    int ViolationCount,
    bool DifferentialEnabled,
    IReadOnlyList<TargetIntelligenceDifferentialRuleDto> DifferentialRules);

public sealed record TargetIntelligenceDifferentialRuleDto(
    string Id,
    string Type,
    string ReferenceExecutable,
    bool ReferenceExists);

public sealed record TargetIntelligenceCampaignDto(
    string RunId,
    DateTimeOffset StartedAt,
    int Iterations,
    int CrashesFound,
    string StalkBackend);

/// <summary>Scare Floor command strip — live campaign posture at a glance.</summary>
public sealed record StalkCommandStripDto(
    double? CoveragePercent,
    int? CoveredBlocks,
    int? TotalBlocks,
    int FrontierCount,
    IReadOnlyDictionary<string, int> CanisterMoods,
    bool DifferentialEnabled);
