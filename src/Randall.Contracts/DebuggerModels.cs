namespace Randall.Contracts;

public sealed record DebuggerToolDto(
    string Id,
    string Name,
    bool Available,
    string? Path,
    string Role,
    string? CommandHint);

public sealed record DebuggerToolsDto(
    IReadOnlyList<DebuggerToolDto> Tools,
    string? PreferredGui,
    string? PreferredWait);

public sealed record DebuggerOpenRequest(
    Guid? CrashId = null,
    string? DumpPath = null,
    string Kind = "auto");

public sealed record DebuggerAttachRequest(
    int? Pid = null,
    string? Project = null,
    string Kind = "auto",
    bool Go = true);

public sealed record DebuggerLaunchResultDto(
    bool Ok,
    string Kind,
    string? Path,
    int? Pid,
    string? DumpPath,
    string Message);
