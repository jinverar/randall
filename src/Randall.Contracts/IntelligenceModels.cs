namespace Randall.Contracts;

/// <summary>Unified fault taxonomy — crash, sanitizer, Page Heap, WER/cdb, oracle-only.</summary>
public enum FaultSignalKind
{
    Unknown,
    AccessViolation,
    StackOverflow,
    StackBufferOverrun,
    HeapCorruption,
    UseAfterFree,
    Sanitizer,
    PageHeap,
    WerClassification,
    OracleOnly,
    Hang,
    IllegalInstruction,
    Other,
}

/// <summary>Where a <see cref="FaultSignal"/> was inferred from.</summary>
public enum FaultSignalSource
{
    Unknown,
    ExitCode,
    MinidumpAnalysis,
    CdbAnalyze,
    LinuxCore,
    PageHeap,
    SanitizerLog,
    OracleRuntime,
    RppPlugin,
    CrashTriage,
    /// <summary>Structured Scream Investigator (expanded CDB probes).</summary>
    DebuggerInvestigation,
}

/// <summary>
/// Normalized fault sensor output — unifies CrashTriage, cdb/!exploitable, Page Heap context,
/// sanitizer stderr, and RPP post_crash tags into one comparable shape for intelligence + FINDINGS.
/// </summary>
public sealed record FaultSignal(
    FaultSignalKind Kind,
    double Confidence,
    string Severity,
    FaultSignalSource Source,
    string? Summary = null,
    string? Detail = null);

/// <summary>Kind of signal emitted on the in-process observation bus.</summary>
public enum ObservationKind
{
    Generic,
    Coverage,
    Path,
    Crash,
    Oracle,
    Ghidra,
    Fault,
    Debugger,
}

/// <summary>
/// Unified fuzz-run observation — common event shape for coverage, crashes, oracle findings, Ghidra hints.
/// Part of the Randall Intelligence Loop (see docs/ORACLES.md).
/// </summary>
public sealed record Observation(
    ObservationKind Type,
    string RunId,
    double Confidence,
    double Novelty,
    string Severity,
    IReadOnlyDictionary<string, object?> Data,
    DateTimeOffset At,
    int Iteration = 0,
    string? InputHash = null,
    string? Project = null);

/// <summary>One explainable term in a Randall / Oracle score (e.g. +30 new coverage).</summary>
public sealed record OracleScoreTerm(string Label, int Points, string? Detail = null);

/// <summary>
/// Explainable interestingness score (0–100) produced by the oracle stack and reused on sidecars / findings.
/// </summary>
public sealed record OracleScore(
    int Total,
    IReadOnlyList<OracleScoreTerm> Terms,
    string Summary)
{
    public static OracleScore Empty { get; } = new(0, [], "");
}

/// <summary>Partial mutator ancestry captured on the crash sidecar / run journal.</summary>
public sealed record CrashLineageDto(
    IReadOnlyList<string> MutatorChain,
    string? ParentInputHash,
    string? SeedSource,
    /// <summary>True when chain is sidecar-only (no full journal replay yet).</summary>
    bool Partial = true);

/// <summary>
/// Formal scream / crash intelligence rollup for Investigation UI, canister mood, and CLI.
/// Aggregates triage, cluster stats, static map, oracle score, and lineage stub.
/// </summary>
public sealed record CrashIntelligenceDto(
    string Severity,
    /// <summary>0–100 — high when cluster is small / first-seen / coverage+oracle signal.</summary>
    int Novelty,
    string? ClusterKey,
    int ClusterSize,
    int? CoverageDelta,
    string? Function,
    int? Offset,
    OracleScore? OracleScore,
    bool Reproducible,
    bool Minimized,
    DateTimeOffset FirstSeen,
    int SeenCount,
    CrashLineageDto? Lineage = null,
    /// <summary>Unified rank for sorting — severity + novelty + oracle + uniqueness.</summary>
    int ScreamScore = 0,
    /// <summary>Primary normalized fault (highest-confidence sensor).</summary>
    FaultSignal? PrimaryFault = null,
    /// <summary>All mapped fault sensors for this crash (triage, cdb, Page Heap, sanitizer, RPP).</summary>
    IReadOnlyList<FaultSignal>? FaultSignals = null,
    /// <summary>One-line canister seal: RIP + static fn + oracle + frontier context.</summary>
    string? CanisterContext = null,
    /// <summary>Nearest gray door or coverage gap relative to crash function.</summary>
    string? FrontierHint = null,
    /// <summary>Scream Investigator diagnosis (CDB sensor).</summary>
    string? DebuggerDiagnosis = null,
    /// <summary>Debugger-aware exploitability hint (HIGH/MEDIUM/LOW).</summary>
    string? DebuggerExploitability = null,
    /// <summary>Research-only input→fault attribution summary when corruption chain exists.</summary>
    string? CorruptionChainSummary = null,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN from corruption chain builder.</summary>
    string? CorruptionConfidence = null,
    /// <summary>Scream evolution family id (phenotype grouping).</summary>
    string? ScreamFamilyId = null,
    /// <summary>0–100 momentum vs ancestors (getting warmer).</summary>
    int ScreamMomentum = 0,
    /// <summary>stable | warming | hot | cooling</summary>
    string? ScreamMomentumLabel = null,
    /// <summary>Lineage generation (1 = root).</summary>
    int ScreamGeneration = 0,
    /// <summary>One-line evolution summary for Investigation / logs.</summary>
    string? ScreamEvolutionSummary = null,
    /// <summary>Phase C top hypothesis id for Investigation / hunt policy.</summary>
    string? TopHypothesisId = null,
    int TopHypothesisConfidence = 0,
    string? TopHypothesisStatement = null,
    /// <summary>Semantic dedup fingerprint (exception/access/stack/oracle/coverage/chain).</summary>
    string? SemanticFingerprint = null,
    bool DeepScreamCandidate = false,
    string? DeepScreamSummary = null,
    bool DeepScreamMinimizedBonus = false,
    /// <summary>Normalized evidence facts for Investigation UI and downstream engines.</summary>
    IReadOnlyList<EvidenceFact>? EvidenceFacts = null,
    /// <summary>Wave 1 root-cause category label for Investigation.</summary>
    string? RootCauseCategory = null,
    /// <summary>Educational root-cause summary (deterministic engine).</summary>
    string? RootCauseSummary = null,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN</summary>
    string? RootCauseConfidence = null,
    /// <summary>Wave 2 research-maturity level (R0…R7) — study depth, not exploit completion.</summary>
    string? ResearchMaturity = null,
    /// <summary>Short label for the maturity level, e.g. "Primitive observed".</summary>
    string? ResearchMaturityLabel = null,
    /// <summary>Deterministic rationale for the maturity level (dense Research-mode evidence).</summary>
    string? ResearchMaturityRationale = null,
    /// <summary>One-line primitive capability rollup for Investigation / list chips.</summary>
    string? PrimitiveSummary = null,
    /// <summary>Count of assessed capability primitives (research-only).</summary>
    int PrimitiveCount = 0,
    /// <summary>One-line ExploitabilityAdvisor teaching summary (packages / posture).</summary>
    string? AdvisorSummary = null,
    /// <summary>Build identity of the analysis engine that produced this rollup (stale-banner).</summary>
    RandallBuildIdentityDto? Engine = null);

/// <summary>In-process observation collector for a single fuzz run.</summary>
public sealed class ObservationBus
{
    private readonly List<Observation> _items = [];
    private readonly object _lock = new();

    public event Action<Observation>? Published;

    public IReadOnlyList<Observation> Snapshot
    {
        get
        {
            lock (_lock)
                return _items.ToList();
        }
    }

    public void Publish(Observation observation)
    {
        lock (_lock)
            _items.Add(observation);
        Published?.Invoke(observation);
    }

    public void Clear()
    {
        lock (_lock)
            _items.Clear();
    }
}

/// <summary>Factory helpers for common observation shapes.</summary>
public static class ObservationEvents
{
    public static Observation Coverage(
        string runId,
        int iteration,
        string inputHash,
        int newEdges,
        int totalEdges,
        string? project = null) =>
        new(
            ObservationKind.Coverage,
            runId,
            Confidence: Math.Clamp(newEdges / 5.0, 0, 1),
            Novelty: newEdges > 0 ? 1.0 : 0.0,
            Severity: newEdges > 0 ? "info" : "none",
            Data: new Dictionary<string, object?>
            {
                ["newEdges"] = newEdges,
                ["totalEdges"] = totalEdges,
            },
            At: DateTimeOffset.UtcNow,
            Iteration: iteration,
            InputHash: inputHash,
            Project: project);

    public static Observation Path(
        string runId,
        int iteration,
        string inputHash,
        int novelPaths,
        int totalPaths,
        string? project = null) =>
        new(
            ObservationKind.Path,
            runId,
            Confidence: Math.Clamp(novelPaths / 3.0, 0, 1),
            Novelty: novelPaths > 0 ? 1.0 : 0.0,
            Severity: novelPaths > 0 ? "info" : "none",
            Data: new Dictionary<string, object?>
            {
                ["novelPaths"] = novelPaths,
                ["totalPaths"] = totalPaths,
            },
            At: DateTimeOffset.UtcNow,
            Iteration: iteration,
            InputHash: inputHash,
            Project: project);

    public static Observation Crash(
        string runId,
        int iteration,
        string inputHash,
        int? exitCode,
        string? detail,
        int newEdgesAtCrash,
        string? project = null) =>
        new(
            ObservationKind.Crash,
            runId,
            Confidence: 0.99,
            Novelty: 1.0,
            Severity: "runtime",
            Data: new Dictionary<string, object?>
            {
                ["exitCode"] = exitCode,
                ["detail"] = detail,
                ["newEdgesAtCrash"] = newEdgesAtCrash,
            },
            At: DateTimeOffset.UtcNow,
            Iteration: iteration,
            InputHash: inputHash,
            Project: project);

    public static Observation OracleEval(
        string runId,
        int iteration,
        string inputHash,
        OracleScore score,
        string maxSeverity,
        int findingCount,
        string? summary,
        string? project = null) =>
        new(
            ObservationKind.Oracle,
            runId,
            Confidence: findingCount > 0 ? 0.85 : 0.4,
            Novelty: score.Total >= 40 ? 0.9 : score.Total / 100.0,
            Severity: maxSeverity,
            Data: new Dictionary<string, object?>
            {
                ["score"] = score.Total,
                ["terms"] = score.Terms,
                ["findings"] = findingCount,
                ["summary"] = summary,
            },
            At: DateTimeOffset.UtcNow,
            Iteration: iteration,
            InputHash: inputHash,
            Project: project);

    public static Observation GhidraHint(
        string runId,
        int iteration,
        string inputHash,
        string hint,
        int priority,
        string? project = null) =>
        new(
            ObservationKind.Ghidra,
            runId,
            Confidence: 0.6,
            Novelty: 0.5,
            Severity: "info",
            Data: new Dictionary<string, object?>
            {
                ["hint"] = hint,
                ["priority"] = priority,
            },
            At: DateTimeOffset.UtcNow,
            Iteration: iteration,
            InputHash: inputHash,
            Project: project);

    public static Observation Fault(
        string runId,
        int iteration,
        string inputHash,
        FaultSignal signal,
        string? project = null) =>
        new(
            ObservationKind.Fault,
            runId,
            Confidence: signal.Confidence,
            Novelty: signal.Severity is "critical" or "high" ? 1.0 : 0.5,
            Severity: signal.Severity,
            Data: new Dictionary<string, object?>
            {
                ["kind"] = signal.Kind.ToString(),
                ["source"] = signal.Source.ToString(),
                ["summary"] = signal.Summary,
                ["detail"] = signal.Detail,
            },
            At: DateTimeOffset.UtcNow,
            Iteration: iteration,
            InputHash: inputHash,
            Project: project);

    public static Observation Debugger(
        string runId,
        int iteration,
        string inputHash,
        DebuggerObservation observation,
        string? project = null) =>
        new(
            ObservationKind.Debugger,
            runId,
            Confidence: observation.Confidence,
            Novelty: observation.DebuggerScreamBonus >= 12 ? 1.0 : 0.6,
            Severity: observation.ExploitabilityHint.Equals("HIGH", StringComparison.OrdinalIgnoreCase)
                ? "critical"
                : "high",
            Data: new Dictionary<string, object?>
            {
                ["diagnosis"] = observation.Diagnosis,
                ["access"] = observation.Access.ToString(),
                ["faultAddress"] = observation.FaultAddress,
                ["rip"] = observation.Rip,
                ["function"] = observation.FaultingFunction,
                ["stackHash"] = observation.StackHash,
                ["inputInfluence"] = observation.SuspectedInputInfluence,
                ["exploitability"] = observation.ExploitabilityHint,
                ["screamBonus"] = observation.DebuggerScreamBonus,
            },
            At: DateTimeOffset.UtcNow,
            Iteration: iteration,
            InputHash: inputHash,
            Project: project);
}
