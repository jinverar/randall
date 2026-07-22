namespace Randall.Contracts;

/// <summary>
/// Missed-block report (Dynapstalker / PaiMei idea): code the campaign has not executed,
/// with heuristics for why and how to revise the fuzzer.
/// </summary>
public sealed record StalkMissedReportDto(
    string Project,
    /// <summary>inventory | relative | empty</summary>
    string Mode,
    string Summary,
    int InventoryCount,
    int HitCount,
    int MissedCount,
    IReadOnlyList<StalkMissedCategoryDto> Categories,
    IReadOnlyList<StalkMissedBlockDto> Blocks,
    IReadOnlyList<MissedFuzzIdeaDto> TopIdeas,
    string WorkflowHint,
    string? InventoryPath = null);

public sealed record StalkMissedCategoryDto(
    string Id,
    string Label,
    int Count,
    string Description);

public sealed record StalkMissedBlockDto(
    string EdgeKey,
    string Address,
    string Module,
    /// <summary>never-hit | baseline-only | module-sparse | session-unexplored | frontier-gap</summary>
    string Category,
    string WhyMissed,
    IReadOnlyList<MissedFuzzIdeaDto> Ideas,
    int PriorityScore,
    string? NearbyHitAddress = null,
    string? SessionCommand = null,
    string? SourceHint = null);

public sealed record MissedFuzzIdeaDto(
    string Id,
    string Title,
    string Detail,
    /// <summary>high | medium | low</summary>
    string Priority,
    string? CliHint = null,
    string? UiHint = null);

public sealed record StalkInventoryImportResultDto(
    string Project,
    string Path,
    int BlockCount,
    string InventoryPath);
