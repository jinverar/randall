namespace Randall.Contracts;

/// <summary>Curated lab library entry — startable servers + linked fuzz profiles.</summary>
public sealed record LabLibraryEntryDto(
    string Id,
    string Name,
    string Description,
    string Category,       // network | drone | iot | robot | ai | exploit-dev | file
    string Difficulty,     // intro | intermediate | advanced
    int Port,
    string Protocol,       // tcp | udp | file
    string ProcessName,
    string ExeRelativePath,
    string ProjectYaml,
    IReadOnlyList<string> Tags,
    bool Startable,
    string? DocsPath = null,
    string? BuildHint = null,
    string BindHint = "127.0.0.1");

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
    string? StatusNote,
    string Category = "network",
    string Difficulty = "intro",
    IReadOnlyList<string>? Tags = null,
    string? DocsPath = null,
    string? BuildHint = null,
    bool Startable = true);

public sealed record LabServerActionResultDto(
    bool Ok,
    string Message,
    string Id,
    int? Pid = null);

public sealed record LabLibraryListDto(
    IReadOnlyList<LabServerInfoDto> Labs,
    IReadOnlyList<string> Categories,
    int RunningCount,
    int BuiltCount);
