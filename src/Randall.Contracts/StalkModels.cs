namespace Randall.Contracts;

public sealed record StalkBlockDto(
    string Id,
    string Label,
    string Address,
    string Kind, // unexplored | hit | novel | crash
    bool IsStart,
    bool IsMutate,
    string Detail = "",
    int PathIndex = -1,
    bool OnCrashPath = false,
    /// <summary>entry | command | handler | crash | fork | block</summary>
    string? Role = null,
    string? Module = null,
    long? HitCount = null,
    string? Command = null,
    string? Prefix = null,
    string? Preamble = null,
    string? ExpectResponse = null,
    string? Model = null,
    string? Mutator = null,
    string? ExceptionHint = null,
    string? FaultModule = null,
    string? Rip = null,
    string? Rsp = null,
    string? Rbp = null,
    string? Severity = null,
    string? CrashClass = null,
    string? ClusterKey = null,
    Guid? CrashId = null,
    int? InputLength = null,
    string? AsciiPreview = null,
    string? HexPreview = null,
    IReadOnlyList<string>? ReHints = null);

public sealed record StalkEdgeDto(
    string From,
    string To,
    string Label,
    bool Taken,
    bool OnCrashPath = false,
    /// <summary>Dominant-path weight — hit count when known (UI stroke thickness).</summary>
    long? HitCount = null);

public sealed record StalkCrashLogDto(
    Guid Id,
    string ShortId,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    int Hits,
    string Exception,
    string Address,
    int? Distance,
    bool NewCoverage,
    string Mutator,
    string InputName,
    string? Severity = null,
    string? CrashClass = null,
    /// <summary>
    /// Honesty label for <see cref="NewCoverage"/>: <c>bb-edges</c>, <c>corpus-novelty</c>, or <c>none</c>.
    /// UI must not render corpus novelty as DynamoRIO BB coverage.
    /// </summary>
    string NewCoverageKind = "none",
    /// <summary>Crash command / mutator focus for notes (not a stale session-graph command).</summary>
    string? Command = null);

public sealed record StalkTimelinePointDto(
    int Index,
    string Kind, // miss | hit | novel | crash
    string Label,
    int Iteration,
    bool Crashed,
    int NewEdges,
    Guid? CrashId = null,
    /// <summary>
    /// Real crash iteration when this bar is pinned into a later timeline window
    /// (<see cref="Iteration"/> stays in-window for sort clients; do not treat host iter as the crash).
    /// </summary>
    int? CrashIteration = null);

public sealed record StalkHotBlockDto(string Address, long Hits);

public sealed record StalkDashboardDto(
    string Project,
    string Kind,
    string Description,
    string ConfigPath,
    string TargetName,
    int? Pid,
    string Arch,
    string Mode,
    string Status,
    bool FuzzRunning,
    int Iterations,
    int Crashes,
    int CoverageEdges,
    int CorpusSize,
    double CoveragePercent,
    string CoverageLabel,
    string CoverageDetail,
    string? SessionId,
    DateTimeOffset? SessionStartedAt,
    string? FuzzerInput,
    string? CrashTime,
    string? Exception,
    string? CrashAddress,
    string? ThreadId,
    string? CrashId,
    int CrashHitCount,
    int? CrashDistance,
    string? FirstDivergence,
    string? BaselineNote,
    int BaselineBlocks,
    int CurrentBlocks,
    int DiffBlocks,
    IReadOnlyList<StalkBlockDto> Blocks,
    IReadOnlyList<StalkEdgeDto> Edges,
    IReadOnlyList<StalkHotBlockDto> TopNewBlocks,
    IReadOnlyList<StalkTimelinePointDto> Timeline,
    IReadOnlyList<StalkCrashLogDto> CrashLog,
    IReadOnlyList<string> Notes,
    string? Mermaid,
    bool DynamoRioAvailable,
    /// <summary>
    /// When true, <see cref="CrashDistance"/> is a session/path-node index — not a real BB distance.
    /// </summary>
    bool CrashDistanceIsSynthetic = false,
    /// <summary>Selected crash mutator/command for mutation-focus notes (overrides stale graph mutate).</summary>
    string? SelectedCrashMutator = null,
    string? SelectedCrashCommand = null);
