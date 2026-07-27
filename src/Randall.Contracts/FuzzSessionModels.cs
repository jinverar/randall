namespace Randall.Contracts;

/// <summary>Completed (or in-progress) fuzz journal under data/runs/ for analyst Open/Import.</summary>
public sealed record FuzzSessionSummaryDto(
    string RunId,
    string Project,
    string Kind,
    DateTimeOffset StartedAt,
    DateTimeOffset? CompletedAt,
    int Iterations,
    int CrashesFound,
    bool CoverageGuided,
    string? Label,
    string Directory,
    bool Saved);

public sealed record FuzzSessionOpenStateDto(
    string? RunId,
    string? Project,
    DateTimeOffset? OpenedAt,
    string? Label = null);

public sealed record FuzzSessionListResultDto(
    IReadOnlyList<FuzzSessionSummaryDto> Sessions,
    string? OpenedRunId,
    string? OpenedProject);

public sealed record FuzzSessionOpenRequest(string RunId);

public sealed record FuzzSessionSaveRequest(
    string? RunId = null,
    string? Project = null,
    string? Label = null);

public sealed record FuzzSessionExportRequest(
    string RunId,
    string? OutputPath = null,
    bool IncludeLinkedCrashes = true);

public sealed record FuzzSessionImportRequest(
    string Path,
    bool Recursive = true,
    bool OverwriteFiles = true);

public sealed record FuzzSessionSaveResultDto(
    string RunId,
    string Project,
    string Label,
    string SavedDir,
    string Message);

public sealed record FuzzSessionExportResultDto(
    string Path,
    string RunId,
    string Project,
    long SizeBytes,
    int CrashCount,
    string Action);

public sealed record FuzzSessionImportResultDto(
    int ImportedRuns,
    int SkippedRuns,
    int ImportedCrashTrees,
    string Message,
    IReadOnlyList<string> RunIds);
