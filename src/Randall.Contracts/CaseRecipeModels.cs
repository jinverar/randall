namespace Randall.Contracts;

/// <summary>One CyberChef-style / Sulley-style block in a case recipe.</summary>
public sealed record CaseStepDto(
    string Op,
    string? Value = null,
    int? Count = null,
    string? Format = null,
    string Role = "fuzzable"); // static | fuzzable — Sulley s_static vs s_string

public sealed record CasePreviewRequest(IReadOnlyList<CaseStepDto> Steps);

public sealed record CasePreviewDto(
    int Length,
    string HexPreview,
    string AsciiPreview,
    string HexFull,
    IReadOnlyList<string> DictionaryHints,
    IReadOnlyList<string> Notes);

public sealed record CaseSaveSeedRequest(
    string Project,
    string FileName,
    IReadOnlyList<CaseStepDto> Steps,
    bool AlsoAddDictionaryHints = true);

public sealed record CaseSaveDictRequest(
    string Project,
    IReadOnlyList<string> Tokens,
    bool AppendToFile = true);

public sealed record CaseSaveResultDto(
    bool Ok,
    string Message,
    string? Path,
    int ByteLength);

public sealed record CaseOpDto(
    string Id,
    string Name,
    string Description,
    string Category,
    IReadOnlyList<string> Fields);

public sealed record CaseSeedInfoDto(
    string FileName,
    string RelativePath,
    int Length,
    string HexPreview,
    string AsciiPreview,
    bool ListedInYaml);

public sealed record CaseProjectProfileDto(
    string Project,
    string Kind,
    string Host,
    int Port,
    bool HasLocalExecutable,
    string? Executable,
    bool LongLived,
    IReadOnlyList<string> Mutators,
    IReadOnlyList<string> AvailableMutators,
    IReadOnlyList<CaseSeedInfoDto> Seeds,
    IReadOnlyList<string> DictionarySample,
    int DictionaryCount,
    string ConfigPath,
    string Tip,
    string Description);

public sealed record CaseMutatorsRequest(
    string Project,
    IReadOnlyList<string> Mutators);

public sealed record CaseNewProjectRequest(
    string Name,
    string Kind, // tcp | udp | file
    string? Description = null,
    string? Host = null,
    int? Port = null,
    string? Executable = null,
    bool LocalFolder = true,
    /// <summary>File targets only — seed / temp file extension (e.g. .bin, .xml, .custom).</summary>
    string? Extension = null,
    /// <summary>file-xml | file-framed | file-magic | file-blank — starter seed shape.</summary>
    string? FileFormat = null);

/// <summary>Partial update of an existing project YAML (null fields = leave unchanged).</summary>
public sealed record CaseUpdateProjectRequest(
    string Project,
    string? Description = null,
    string? Host = null,
    int? Port = null,
    string? Executable = null,
    bool? LongLived = null);

public sealed record CaseImportBytesRequest(
    string? Hex = null,
    string? Text = null,
    string? Base64 = null);

public sealed record CaseImportBytesDto(
    int Length,
    string HexPreview,
    string AsciiPreview,
    IReadOnlyList<CaseStepDto> SuggestedSteps);
