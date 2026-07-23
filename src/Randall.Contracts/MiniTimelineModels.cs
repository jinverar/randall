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
    string? Directory = null);
