namespace Randall.Contracts;

/// <summary>Start a managed target under Target Runtime (local or agent).</summary>
public sealed record TargetRuntimeStartRequest(
    string Id,
    string Executable,
    IReadOnlyList<string>? Args = null,
    string? WorkingDirectory = null,
    int? WaitPort = null,
    string? WaitHost = null,
    bool PageHeap = false,
    string? ProjectYaml = null,
    string? WaitProtocol = null,
    IReadOnlyList<PostStartActionConfig>? PostStart = null,
    string? CasePath = null);

/// <summary>Live status of one runtime slot.</summary>
public sealed record TargetRuntimeStatusDto(
    string Id,
    bool Ok,
    string Message,
    bool Running,
    int? Pid,
    string? Executable,
    IReadOnlyList<string>? Args,
    string? WorkingDirectory,
    int? WaitPort,
    string? WaitHost,
    bool? PortReachable,
    bool PageHeap,
    string? ProjectYaml,
    DateTimeOffset? StartedAtUtc,
    int? LastExitCode,
    DateTimeOffset? StoppedAtUtc,
    string? MachineName);

/// <summary>List wrapper for API clients.</summary>
public sealed record TargetRuntimeListDto(
    string MachineName,
    IReadOnlyList<TargetRuntimeStatusDto> Slots);
