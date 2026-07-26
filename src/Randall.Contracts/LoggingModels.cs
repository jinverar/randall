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
    DateTimeOffset ObservedAt,
    /// <summary>Analysis-oriented intel (exploit-test probes + GDB) — triage only, no payloads.</summary>
    CrashIntelDto? Intel = null,
    /// <summary>Unified Randall interestingness score at crash time (oracle + coverage terms).</summary>
    OracleScore? RandallScore = null,
    /// <summary>True when bottled from a high oracle violation without a memory crash (Wave 5 silent scream).</summary>
    bool SilentScream = false,
    string? OracleFindingId = null,
    string? OracleRuleClass = null,
    string? OracleRuleId = null);

/// <summary>
/// Post-crash intelligence for analysts: what to probe next and which GDB commands to run.
/// Explicitly not an exploit recipe — no shellcode / payloads.
/// </summary>
public sealed record CrashIntelDto(
    string Headline,
    string Hypothesis,
    IReadOnlyList<string> Findings,
    IReadOnlyList<string> ExploitTestRecommendations,
    IReadOnlyList<string> RecipeRecommendations,
    IReadOnlyList<string> CoverageNotes,
    IReadOnlyList<string> GdbCommands,
    IReadOnlyList<string> NextCliCommands,
    string Disclaimer = "Triage & research only — no shellcode, weaponized payloads, or exploit templates.");

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
    int CrashesFound,
    IReadOnlyList<HotEdgeDto>? HotEdges = null);

public sealed record HotEdgeDto(string Edge, long HitCount);

/// <summary>Per-mutator credit row (mutator_stats.json + leaderboard).</summary>
public sealed record MutatorCreditRowDto(
    string Name,
    int Runs,
    int NewEdges,
    int UniqueCrashes,
    double Score,
    int SelectionWeight,
    /// <summary>Runs with zero new edges — Hunt Policy execution cost.</summary>
    int StaleRuns = 0,
    /// <summary>Fraction of runs with no edges and no unique crash [0–1].</summary>
    double FailureRate = 0);

/// <summary>Run-scoped mutator credit export under data/runs/&lt;runId&gt;/.</summary>
public sealed record MutatorCreditRunDto(
    bool BiasEnabled,
    IReadOnlyList<MutatorCreditRowDto> Mutators);

public sealed record MutatorChainRowDto(
    IReadOnlyList<string> Chain,
    int Runs,
    int NewEdges,
    int UniqueCrashes,
    double Score,
    int SelectionWeight,
    string DisplayLabel);

public sealed record MutatorChainTransitionRowDto(
    string From,
    string To,
    int Runs,
    int NewEdges,
    int UniqueCrashes,
    double Score);

public sealed record MutatorChainStoreDto(
    bool BiasEnabled,
    IReadOnlyList<MutatorChainRowDto> Pairs,
    IReadOnlyList<MutatorChainRowDto> Triples,
    IReadOnlyList<MutatorChainTransitionRowDto> Transitions);

public sealed record RegisterSnapshotDto(
    string? Rip,
    string? Rsp,
    string? Rbp,
    string? Rax,
    string? Rbx,
    string? Rcx,
    string? Rdx);

/// <summary>Minidump triage output (*_analysis.json).</summary>
public sealed record CrashAnalysisDto(
    bool Ok,
    string? DumpPath,
    string? ExceptionCode,
    string? ExceptionHint,
    string? FaultAddress,
    string? FaultModule,
    RegisterSnapshotDto? Registers,
    IReadOnlyList<string> LoadedModules,
    string? Error);

/// <summary>Research-oriented crash taxonomy (severity / class — not exploit tooling).</summary>
public sealed record CrashTriageDto(
    string Class,
    string Severity,
    string Summary,
    bool IpLooksControlled,
    bool StackLooksSmashed,
    string ClusterKey,
    string? ExceptionHint,
    string? FaultAddress,
    string? FaultModule,
    string? Rip,
    string? Rsp,
    int? PatternDepthBytes = null,
    string? PatternNote = null,
    StaticFunctionMappingDto? StaticFunction = null,
    /// <summary>Semantic dedup key — exception/access/stack/oracle/coverage/chain (parallel to ClusterKey).</summary>
    string? SemanticFingerprint = null);
