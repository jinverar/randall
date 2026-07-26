namespace Randall.Contracts;

/// <summary>
/// End-of-campaign / end-of-run teaching postmortem.
/// Persisted at <c>data/runs/&lt;project&gt;/&lt;runId&gt;_postmortem.json</c>
/// or <c>data/stalk/&lt;project&gt;/campaign_postmortem_last.json</c>.
/// Research/teaching only — never exploit automation.
/// </summary>
public sealed record CampaignPostmortemDto(
    bool Ok,
    string Project,
    string? RunId,
    DateTimeOffset At,
    int Iterations,
    int UniqueCrashes,
    int CorpusGrowth,
    IReadOnlyList<string> TopMutators,
    IReadOnlyList<BarrierItemDto> Barriers,
    IReadOnlyList<string> ScreamFamilies,
    string? StopGoalSummary,
    /// <summary>Plain-language teaching narrative: what worked, what stalled, next packages.</summary>
    string NarrativeSummary,
    IReadOnlyList<string> WhatWorked,
    IReadOnlyList<string> WhatStalled,
    /// <summary>Teaching package names (see <see cref="TeachingPackages"/>).</summary>
    IReadOnlyList<string> NextResearchPackages,
    string? Error = null);

/// <summary>Optional stats bag when building a postmortem without re-scanning the filesystem.</summary>
public sealed record CampaignPostmortemInput(
    string Project,
    string? RunId = null,
    int Iterations = 0,
    int UniqueCrashes = 0,
    int CorpusGrowth = 0,
    IReadOnlyList<MutatorCreditRowDto>? MutatorRows = null,
    IReadOnlyList<BarrierItemDto>? Barriers = null,
    IReadOnlyList<string>? ScreamFamilies = null,
    IntelligenceStopGoalProgressDto? StopGoals = null,
    string? StopReason = null);
