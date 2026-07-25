namespace Randall.Contracts;

/// <summary>Kind of signal emitted on the in-process observation bus.</summary>
public enum ObservationKind
{
    Generic,
    Coverage,
    Path,
    Crash,
    Oracle,
    Ghidra,
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
    int ScreamScore = 0);

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
}
