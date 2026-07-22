namespace Randall.Contracts;

/// <summary>Portable crash tree for offline backup / import into another console.</summary>
public sealed record CrashArtifactPackManifest(
    int Version,
    string Kind,
    string Project,
    DateTimeOffset ExportedAt,
    string SourceHost,
    string SourceCrashesDir,
    string? SourceRunsDir,
    bool IncludeRuns,
    int CrashCount,
    int RunCount);

public sealed record CrashArtifactPackRequest(
    string Project,
    string? OutputPath = null,
    bool IncludeRuns = true);

public sealed record CrashArtifactPackPullRequest(
    string AgentUrl,
    string Project,
    string? OutputPath = null,
    bool IncludeRuns = true,
    string? AgentToken = null);

public sealed record CrashArtifactPackImportRequest(
    string ZipPath,
    bool OverwriteFiles = true);

public sealed record CrashArtifactPackResultDto(
    string Path,
    string Project,
    long SizeBytes,
    int CrashCount,
    int RunCount,
    string Action);

public sealed record CrashArtifactPackImportResultDto(
    string Project,
    string CrashesDir,
    int ImportedCrashes,
    int SkippedCrashes,
    int ImportedRuns,
    string Message);
