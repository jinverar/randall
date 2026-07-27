namespace Randall.Contracts;

/// <summary>Headless CDB script profile — one plan per use case.</summary>
public enum CdbProbePlan
{
    /// <summary>Post-mortem minidump triage (!analyze + register/stack/heap probes).</summary>
    StandardCrash,
    /// <summary>Heap-only enrichment (!heap -s / !heap -p).</summary>
    HeapCrash,
    /// <summary>Extended post-mortem (same probes as <see cref="StandardCrash"/>; reserved for TTD/Deep Scream).</summary>
    DeepScream,
    /// <summary>WinDbg GUI open script beside a canister (metadata + r/k/lm).</summary>
    InteractiveOpen,
    /// <summary>Live attach — second-chance dump policy.</summary>
    WaitAttach,
}

/// <summary>Named RANDFUZZ_* transcript sections produced by <see cref="CdbProbeSection"/> markers.</summary>
public enum CdbProbeSection
{
    Analyze,
    Exception,
    Context,
    Regs,
    Stack,
    Disasm,
    Instruction,
    Symbol,
    Memory,
    Heap,
    PageHeap,
    Modules,
    Address,
    Exploitable,
    WaitAttach,
    CrashCapture,
}

/// <summary>Whether a debugger fact was read from CDB output or inferred heuristically.</summary>
public enum DebuggerFactKind
{
    Observed,
    Inferred,
}

/// <summary>Confidence tier for a single debugger-derived fact.</summary>
public enum DebuggerFactConfidence
{
    High,
    Medium,
    Low,
    Unknown,
}

/// <summary>One provenance-tracked value from a CDB probe or downstream inference.</summary>
public sealed record DebuggerFactDto<T>(
    T? Value,
    string? Source,
    DebuggerFactConfidence Confidence,
    DebuggerFactKind Kind);

/// <summary>
/// Provenance for key <see cref="DebuggerObservation"/> fields — optional parallel DTO so existing consumers stay stable.
/// </summary>
public sealed record DebuggerObservationProvenance(
    DebuggerFactDto<string>? ExceptionCode = null,
    DebuggerFactDto<string>? ExceptionHint = null,
    DebuggerFactDto<string>? FaultAddress = null,
    DebuggerFactDto<DebuggerAccessKind>? Access = null,
    DebuggerFactDto<string>? Rip = null,
    DebuggerFactDto<string>? FaultingModule = null,
    DebuggerFactDto<string>? FaultingFunction = null,
    DebuggerFactDto<DebuggerAddressClass>? FaultAddressClass = null,
    DebuggerFactDto<string>? ExploitableClassification = null,
    DebuggerFactDto<string>? HeapSignal = null);
