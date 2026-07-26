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
/// Payload offset where a debugger register value matches input bytes (research triage).
/// Populated by <see cref="InputAttributionEngine"/> and optionally by headless CDB register probes.
/// </summary>
public sealed record RegisterPayloadMatchDto(
    string Register,
    string ValueHex,
    int PayloadOffset,
    int WidthBytes,
    /// <summary>dword / qword / ascii</summary>
    string MatchKind,
    string? Note = null);

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
    string? Error = null,
    /// <summary>0-based index into <see cref="MutatorLineage"/> when a specific step is attributed.</summary>
    int? SuspectedMutatorStep = null,
    /// <summary>Register ↔ payload correlations (RAX/RCX/… dword/qword/ASCII).</summary>
    IReadOnlyList<RegisterPayloadMatchDto>? RegisterMatches = null,
    /// <summary>Primary register driving the fault when known.</summary>
    string? PrimaryRegister = null,
    /// <summary>Exploit-triage narrative: field → register → sink → AV → heap.</summary>
    string? Narrative = null,
    /// <summary>Extra ScreamScore contribution when attribution is high-confidence.</summary>
    int AttributionScreamBonus = 0);
