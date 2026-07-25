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
    TargetIntelligenceDto? TargetProfile = null,
    NextHuntDecision? LastBrainDecision = null);

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
    OracleScore? ScoreBreakdown,
    int ApproachCount = 0,
    int CrossedCount = 0,
    int Attempts = 0,
    double ClosestDistance = 0,
    string? LastProgress = null,
    string? BestSeedId = null,
    string? BestMutation = null,
    int StaticScore = 0,
    double ProgressFraction = 0);

/// <summary>POST body for <c>/api/stalking/{project}/hunt</c> — pin brain focus for the next fuzz run.</summary>
public sealed record StalkHuntRequest(
    string FocusKind,
    string FocusLabel,
    string? Address = null);
