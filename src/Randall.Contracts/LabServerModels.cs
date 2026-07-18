namespace Randall.Contracts;

public sealed record LabServerInfoDto(
    string Id,
    string Name,
    string Description,
    int Port,
    string Protocol,
    string ProcessName,
    string ExeRelativePath,
    string ProjectYaml,
    bool ExeExists,
    bool Running,
    int? Pid,
    bool Reachable,
    string BindHint,
    string? StatusNote);

public sealed record LabServerActionResultDto(
    bool Ok,
    string Message,
    string Id,
    int? Pid = null);
