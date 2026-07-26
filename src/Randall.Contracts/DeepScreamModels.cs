namespace Randall.Contracts;

/// <summary>
/// Phase D — Deep Scream gate: expensive rewind/TTD operator path only for high-value screams.
/// Persisted as <c>{guid}_deep_scream.json</c> next to crash sidecars.
/// </summary>
public sealed record DeepScreamDto(
    bool Ok,
    bool IsCandidate,
    Guid CrashId,
    string Project,
    int ScreamScore,
    int SeenCount,
    bool Reproducible,
    bool Minimized,
    IReadOnlyList<string> EligibilityReasons,
    IReadOnlyList<string> MissingReasons,
    string? DumpPath = null,
    string? EvolutionPath = null,
    string? CorruptionChainPath = null,
    string? BackwardTracePath = null,
    string? HypothesisPath = null,
    string? SemanticFingerprint = null,
    string? FamilyId = null,
    bool IsMarked = false,
    bool FamilySuppressed = false,
    Guid? PriorFamilyCrashId = null,
    bool AutoMinimizeAttempted = false,
    bool AutoMinimizeSucceeded = false,
    string? MinimizedInputPath = null,
    bool TtdToolsPresent = false,
    string? TtdToolsSummary = null,
    string? TtdHintPath = null,
    string? TtdRecordScriptPath = null,
    string? TtdReplayScriptPath = null,
    string? TtdLaunchNote = null,
    DateTimeOffset At = default,
    string? Error = null);

public sealed record DeepScreamFamilyEntryDto(
    Guid CrashId,
    int ScreamScore,
    int MomentumScore,
    string? MomentumLabel,
    ScreamProgressionStep ProgressionStep,
    DateTimeOffset At);
