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
    DateTimeOffset ObservedAt);

public sealed record CrashDetailDto(
    CrashSummaryDto Summary,
    int InputLength,
    string HexPreview);
