namespace Randall.Contracts;

/// <summary>
/// Scare Floor "Randall thinks" rollup — frontier gray doors, static fuzzPriority, oracle hints, mutator credit.
/// Built from on-disk stalk artifacts under <c>data/stalk/&lt;project&gt;/</c>.
/// </summary>
public sealed record StalkIntelligenceDto(
    string Project,
    bool HasData,
    string Summary,
    string EmptyHint,
    string? FrontierMode,
    string? FrontierSummary,
    string? StaticSummary,
    string? CoverageGapSummary,
    int OracleFindingCount,
    IReadOnlyList<StalkIntelligenceTargetDto> Targets,
    IReadOnlyList<MutatorCreditRowDto> TopMutators,
    bool MutatorBiasEnabled,
    StalkCommandStripDto? CommandStrip = null,
    TargetIntelligenceDto? TargetProfile = null);

/// <summary>One ranked scare target with optional explainable score breakdown for the Why? control.</summary>
public sealed record StalkIntelligenceTargetDto(
    string Id,
    /// <summary>frontier | static | oracle | patch</summary>
    string Kind,
    string Label,
    int Score,
    string Detail,
    string? Address,
    string? FunctionName,
    OracleScore? ScoreBreakdown);
