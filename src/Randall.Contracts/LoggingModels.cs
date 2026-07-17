namespace Randall.Contracts;

/// <summary>Per-iteration execution log (iterations.jsonl).</summary>
public sealed record IterationLogEntry(
    int Iteration,
    DateTimeOffset At,
    string Command,
    string Mutator,
    IReadOnlyList<string> MutatorChain,
    string? ParentInputHash,
    string SeedSource,
    int PayloadLength,
    string PayloadHash,
    bool Crashed,
    int NewEdges,
    int TotalEdges,
    long ElapsedMs,
    string TargetDetail,
    int? ExitCode,
    string StalkBackend,
    string? TracePath,
    string RunId,
    bool DryRun);

/// <summary>Rich crash metadata (crash.json) — survives index.jsonl and powers triage export.</summary>
public sealed record CrashSidecarDto(
    Guid CrashId,
    string RunId,
    int Iteration,
    string Project,
    string Command,
    string Mutator,
    IReadOnlyList<string> MutatorChain,
    string? ParentInputHash,
    string SeedSource,
    IReadOnlyList<string> SeedFiles,
    string InputHash,
    string InputPath,
    int InputLength,
    int? ExitCode,
    string? ExceptionHint,
    string TargetDetail,
    string? TriageTag,
    int NewEdgesAtCrash,
    int TotalEdgesAtCrash,
    string StalkBackend,
    string? TracePath,
    string? TraceCopyPath,
    string? MiniDumpPath,
    string? ResponseHex,
    TransportSnapshotDto Transport,
    FuzzSnapshotDto FuzzSnapshot,
    DateTimeOffset ObservedAt);

public sealed record TransportSnapshotDto(string Kind, string Host, int Port, bool Tls);

public sealed record FuzzSnapshotDto(
    bool CoverageGuided,
    bool DryRun,
    string ConfigPath);

public sealed record FuzzRunManifestDto(
    string RunId,
    string Project,
    string Kind,
    string ConfigPath,
    DateTimeOffset StartedAt,
    DateTimeOffset? CompletedAt,
    bool DryRun,
    bool CoverageGuided,
    string StalkBackend,
    string StalkBackendNote,
    int Iterations,
    int CrashesFound);
