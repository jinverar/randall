namespace Randall.Contracts;

public sealed record RoadmapItemDto(string Id, string Title, bool Done, string? Note);

public sealed record RoadmapPhaseDto(
    int Phase,
    string Title,
    string Status,
    IReadOnlyList<RoadmapItemDto> Items);

public sealed record TargetProfileDto(
    string Name,
    string Kind,
    string Description,
    string ConfigPath);

public sealed record CrashSummaryDto(
    Guid Id,
    string Project,
    int Iteration,
    string Mutator,
    string InputHash,
    string InputPath,
    string? MiniDumpPath,
    string? TargetExitCode,
    string? TriageTag,
    DateTimeOffset ObservedAt);

public sealed record SessionGraphEdgeDto(string From, string When, string To);

public sealed record SessionGraphReportDto(
    string Project,
    bool HasGraph,
    bool Valid,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings,
    string Mermaid,
    string? Start,
    string? Mutate,
    IReadOnlyList<SessionGraphEdgeDto> Edges,
    IReadOnlyList<string> Commands,
    string YamlSnippet);

public sealed record CrashDetailDto(
    CrashSummaryDto Summary,
    int InputLength,
    string HexPreview);

public sealed record CrashClusterDto(
    string ClusterId,
    string Project,
    int Count,
    Guid RepresentativeId,
    string RepresentativeHash,
    string RepresentativeMutator,
    int LengthBucket);

public sealed record DoctorCheckDto(string Id, string Status, string Message);

public sealed record DoctorReportDto(
    string Project,
    bool Ready,
    IReadOnlyList<DoctorCheckDto> Checks);
