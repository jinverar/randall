namespace Randall.Contracts;

/// <summary>
/// One step in a suspected input → fault corruption chain (research triage).
/// </summary>
public sealed record CorruptionChainStepDto(
    int Order,
    string Kind,
    string Label,
    string? Detail = null);

/// <summary>
/// Input attribution / corruption hypothesis linking mutation lineage to debugger evidence.
/// Persisted as <c>{guid}_corruption_chain.json</c>.
/// </summary>
public sealed record CrashCorruptionChainDto(
    bool Ok,
    Guid CrashId,
    string Project,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN</summary>
    string Confidence,
    string Summary,
    string? SuspectedField,
    string? SuspectedMutator,
    int? PatternDepthBytes,
    string? PatternNote,
    IReadOnlyList<string> MutatorLineage,
    IReadOnlyList<CorruptionChainStepDto> Steps,
    string? DebuggerDiagnosis,
    string? StackHash,
    DateTimeOffset At,
    string? Error = null);
