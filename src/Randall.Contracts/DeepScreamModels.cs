namespace Randall.Contracts;

/// <summary>
/// Phase D — Deep Scream gate: expensive rewind/TTD operator path only for high-value screams.
/// Persisted as <c>{guid}_deep_scream.json</c> next to crash sidecars.
/// </summary>
public sealed record DeepScreamDto(
    bool Ok,
    /// <summary>True when screamScore, uniqueness, and reproducibility gates pass.</summary>
    bool IsCandidate,
    Guid CrashId,
    string Project,
    int ScreamScore,
    int SeenCount,
    bool Reproducible,
    bool Minimized,
    /// <summary>Explain why eligible (and optional minimized bonus).</summary>
    IReadOnlyList<string> EligibilityReasons,
    /// <summary>Why not a candidate when <see cref="IsCandidate"/> is false.</summary>
    IReadOnlyList<string> MissingReasons,
    string? DumpPath = null,
    string? EvolutionPath = null,
    string? CorruptionChainPath = null,
    /// <summary>Per-crash TTD operator hint when rewind/TTD path runs.</summary>
    string? TtdHintPath = null,
    DateTimeOffset At = default,
    string? Error = null);
