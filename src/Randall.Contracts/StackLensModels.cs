namespace Randall.Contracts;

/// <summary>
/// Stack Lens — dump-native CONTROL map (stack slots × crashing input).
/// Lab-only; no shellcode / payloads. See docs/WINDBG_FUZZ_PKG.md.
/// </summary>
public sealed record StackLensRequest(
    Guid CrashId,
    int WindowBytes = 128,
    string? Exe = null);

public sealed record StackLensWordDto(
    int OffsetFromSp,          // bytes from SP (RSP/ESP)
    string AddressHex,         // VA of this slot when known
    string ValueHex,           // word value
    string Role,               // controlled | return-slot | frame-ptr | canary-suspect | unknown
    int? InputOffset = null,   // offset into crashing input / cyclic
    string? SymbolHint = null, // module!+rva or nearest export
    string? Note = null);

public sealed record StackLensPrimaryControlDto(
    string Where,              // RIP | RSP+0x08 | stack …
    string ValueHex,
    int? InputOffset,
    string Role);

public sealed record StackLensReportDto(
    Guid CrashId,
    string Project,
    string Arch,               // x64 | x86 | unknown
    string? SpRegister,        // RSP | ESP
    string? SpValue,
    int WindowBytes,
    int WordSize,
    IReadOnlyList<StackLensWordDto> Words,
    StackLensPrimaryControlDto? PrimaryControl,
    IReadOnlyList<string> Hints,
    string SummaryLine,
    string Source,             // gdb-core | minidump | registers-only | none
    string? OutputPath = null,
    string? Error = null,
    string? DumpPath = null,
    string? ExePath = null);
