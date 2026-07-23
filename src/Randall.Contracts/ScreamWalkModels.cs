namespace Randall.Contracts;

/// <summary>
/// Scream Walk — ordered scream → CONTROL → sketch → debugger walk playbook.
/// Lab-only; no shellcode / payloads. See docs/WINDBG_FUZZ_PKG.md.
/// </summary>
public sealed record ScreamWalkStepDto(
    int Index,
    string Id,          // stack | badchars | sketch | windbg | gdb | guide | ladder
    string Title,
    string Status,      // ok | skip | fail | info
    string? Detail = null,
    IReadOnlyList<string>? Commands = null,
    string? ArtifactPath = null);

public sealed record ScreamWalkRequest(
    Guid CrashId,
    string Goal = "auto",       // auto | control | pivot | write | leak | canary
    string? BadCharsHex = null,
    string? Exe = null,
    int MaxModules = 3,
    bool OpenHints = true);

public sealed record ScreamWalkReportDto(
    Guid CrashId,
    string Project,
    string GoalResolved,
    string? ControlledRegister,
    int? ControlledOffset,
    string? MitigationTier,
    IReadOnlyList<ScreamWalkStepDto> Steps,
    string SummaryLine,
    string? PlaybookPath = null,
    string? RopPath = null,
    string? WalkPath = null,
    string? GdbWalkPath = null,
    string? BadCharsPath = null,
    string? StackLensPath = null,
    string? Error = null);

public sealed record LadderTierRowDto(
    string Tier,          // basic | nx | aslr | modern | unknown
    string? ExePath,
    bool Exists,
    bool Nx,
    bool Canary,
    bool Pie,
    string Relro,
    bool Fortify,
    int? GadgetCount = null,
    int? RetCount = null,
    int? PivotCount = null,
    int? PltCount = null,
    string? SketchGoalHint = null,
    string? Note = null);

public sealed record LadderDiffRequest(
    Guid? CrashId = null,
    string? Project = null);

public sealed record LadderDiffReportDto(
    string LabRoot,
    IReadOnlyList<LadderTierRowDto> Tiers,
    IReadOnlyList<string> Findings,
    IReadOnlyList<string> NextCommands,
    string SummaryLine,
    Guid? CrashId = null,
    string? ControlledRegister = null,
    int? ControlledOffset = null,
    string? OutputPath = null,
    string? Error = null);

public sealed record GdbWalkReportDto(
    Guid? CrashId,
    string? CorePath,
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
