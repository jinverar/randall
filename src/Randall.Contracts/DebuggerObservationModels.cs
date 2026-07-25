namespace Randall.Contracts;

/// <summary>
/// Access type inferred for ACCESS_VIOLATION-style faults.
/// </summary>
public enum DebuggerAccessKind
{
    Unknown,
    Read,
    Write,
    Execute,
}

/// <summary>
/// Coarse classification of the faulting address (null page, ASCII, heap-ish, etc.).
/// </summary>
public enum DebuggerAddressClass
{
    Unknown,
    NullPage,
    SmallOffset,
    AsciiPattern,
    NonCanonical,
    ModuleRange,
    Stackish,
    Heapish,
    Other,
}

/// <summary>One stack frame from headless CDB <c>kv</c>.</summary>
public sealed record DebuggerStackFrameDto(
    int Index,
    string? Address,
    string? Module,
    string? Symbol,
    string? Offset);

/// <summary>
/// Structured debugger sensor output — CDB headless triage normalized for Brain / Scream / UI.
/// Written as <c>{guid}_debugger_observation.json</c> by <c>ScreamInvestigator</c>.
/// </summary>
public sealed record DebuggerObservation(
    bool Ok,
    string? DumpPath,
    string? ObservationPath,
    string? ExceptionCode,
    string? ExceptionHint,
    DebuggerAccessKind Access,
    string? FaultAddress,
    DebuggerAddressClass FaultAddressClass,
    string? Rip,
    string? FaultingModule,
    string? FaultingFunction,
    string? FunctionOffset,
    IReadOnlyList<DebuggerStackFrameDto> Stack,
    string? StackHash,
    string? RegistersText,
    string? DisasmNearRip,
    string? MemoryNearRsp,
    string? ExrText,
    string? ExploitableClassification,
    string? ExploitableDescription,
    string? HeapSignal,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN — input influence guess from address/reg patterns.</summary>
    string SuspectedInputInfluence,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN</summary>
    string ExploitabilityHint,
    double Confidence,
    /// <summary>Human-readable Scream diagnosis paragraph for the canister / Brain.</summary>
    string Diagnosis,
    /// <summary>0–100 debugger-aware contribution fused into ScreamScore.</summary>
    int DebuggerScreamBonus,
    bool AnalyzeTimedOut,
    string? Error,
    DateTimeOffset At);
