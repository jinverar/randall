namespace Randall.Contracts;

/// <summary>Summary of a crash-scoped Windows mini-timeline (EZ tools). See docs/MINI_TIMELINE.md.</summary>
public sealed record MiniTimelineSummaryDto(
    bool Ok,
    string? Error,
    Guid CrashId,
    string? Project,
    string? TargetExe,
    DateTimeOffset AnchorUtc,
    DateTimeOffset WindowStartUtc,
    DateTimeOffset WindowEndUtc,
    int WindowSeconds,
    IReadOnlyList<string> ToolsUsed,
    IReadOnlyList<string> Artifacts,
    int EvtxRows,
    int MftRows,
    int PrefetchRows,
    int AmcacheRows,
    int WerCopied,
    IReadOnlyList<string> Notes,
    string SummaryLine,
    DateTimeOffset CapturedAtUtc,
    int AppCompatRows = 0,
    string? BstringsPath = null,
    string? Directory = null,
    int ProcmonRows = 0,
    string? GraphPath = null,
    string? ProcmonPml = null);

public sealed record MiniTimelineGraphDto(
    string CrashId,
    string? Project,
    DateTimeOffset AnchorUtc,
    IReadOnlyList<MiniTimelineGraphNodeDto> Nodes,
    IReadOnlyList<MiniTimelineGraphEdgeDto> Edges,
    string SummaryLine);

public sealed record MiniTimelineGraphNodeDto(
    string Id,
    string Kind,
    string Label,
    IReadOnlyDictionary<string, string>? Properties = null);

public sealed record MiniTimelineGraphEdgeDto(
    string From,
    string To,
    string Kind,
    string? Label = null);
