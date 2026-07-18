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
    bool OnCrashPath = false);

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
    string? CrashClass = null);

public sealed record StalkTimelinePointDto(
    int Index,
    string Kind, // miss | hit | novel | crash
    string Label,
    int Iteration,
    bool Crashed,
    int NewEdges);

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
    bool DynamoRioAvailable);
