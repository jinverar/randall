namespace Randall.Contracts;

/// <summary>
/// ROP Studio — gadget catalog + constrained chain sketches for lab exploit-dev.
/// No shellcode / weaponized payloads. See docs/WINDBG_FUZZ_PKG.md.
/// </summary>
public sealed record RopGadgetDto(
    string Address,       // VA hex 0x…
    string Kind,          // ret | pop-rax | add-sp | …
    string BytesHex,
    string Instruction,
    string Module,
    int Size,
    IReadOnlyList<string> Tags,
    string? Symbol = null); // nearest PE export / ELF hint

public sealed record RopScanReportDto(
    string ModulePath,
    string Arch,          // x64 | x86 | unknown
    string ModuleSha256,
    int ExecutableBytes,
    int GadgetCount,
    IReadOnlyList<RopGadgetDto> Gadgets,
    string SummaryLine,
    string? CachePath = null,
    string? Error = null);

public sealed record RopSearchRequest(
    string? Exe = null,
    string? Need = null,          // pop-rcx | ret | pivot | …
    string? BadCharsHex = null,   // "00 0a 0d" or "\x00\x0a"
    int Limit = 40,
    Guid? CrashId = null);

public sealed record RopSearchReportDto(
    string ModulePath,
    string Need,
    IReadOnlyList<RopGadgetDto> Hits,
    string SummaryLine,
    IReadOnlyList<string>? RejectedReasons = null);

public sealed record RopSketchRequest(
    string? Exe = null,
    string Goal = "control",      // control | pivot | write
    string? BadCharsHex = null,
    int MaxSteps = 8);

public sealed record RopSketchStepDto(
    int Index,
    string Role,                  // entry | load-reg | pivot | ret
    RopGadgetDto Gadget,
    string Why);

public sealed record RopSketchReportDto(
    string ModulePath,
    string Goal,
    string Arch,
    IReadOnlyList<RopSketchStepDto> Steps,
    string SummaryLine,
    IReadOnlyList<string> Constraints,
    string? OutputPath = null,
    string? Error = null,
    IReadOnlyList<string>? ModulesScanned = null);

public sealed record RopFromCrashRequest(
    Guid CrashId,
    string Goal = "pivot",
    string? BadCharsHex = null,
    string? Exe = null,
    int MaxModules = 3);

public sealed record WindbgWalkReportDto(
    Guid? CrashId,
    string? DumpPath,
    string? Project,
    string? ControlledRegister,
    int? ControlledOffset,
    IReadOnlyList<string> Registers,
    IReadOnlyList<string> Modules,
    IReadOnlyList<string> ScriptLines,
    string SummaryLine,
    string? WalkPath = null,
    string? RopPath = null,
    string? BadCharsPath = null,
    string? Error = null,
    string? ExceptionHint = null,
    IReadOnlyList<string>? ModuleCandidates = null);

public sealed record RopBadCharReportDto(
    Guid? CrashId,
    string? Project,
    IReadOnlyList<byte> Suggested,
    string BadCharsHex,           // \x00\x0a form for --badchars
    string SummaryLine,
    IReadOnlyList<string>? Reasons = null,
    int? ControlOffset = null,
    int? InputLength = null,
    string? OutputPath = null,
    string? Error = null);

public sealed record RopBadCharRequest(Guid CrashId);

/// <summary>Existing ROP Studio / RandfuzzDbg sidecars beside a scream canister.</summary>
public sealed record RopSidecarsDto(
    Guid CrashId,
    string Project,
    string? RopPath,
    string? WalkPath,
    string? BadCharsPath,
    string? GuidePath,
    RopSketchReportDto? Sketch,
    WindbgWalkReportDto? Walk,
    RopBadCharReportDto? BadChars,
    string SummaryLine);
