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
    string? Base64 = null,
    /// <summary>Optional original filename — used for suggested seed name / format hints.</summary>
    string? FileName = null);

public sealed record CaseImportBytesDto(
    int Length,
    string HexPreview,
    string AsciiPreview,
    IReadOnlyList<CaseStepDto> SuggestedSteps,
    string? DetectedFormat = null,
    IReadOnlyList<string>? Notes = null,
    string? SuggestedSeedName = null);

/// <summary>Write an uploaded sample byte-for-byte as a project seed (exact file, not recipe-rendered).</summary>
public sealed record CaseSaveRawSeedRequest(
    string Project,
    string FileName,
    string Base64,
    bool AlsoImportRecipe = true);

/// <summary>Named layer in a Scapy-style PDU stack (flattens to Blocks on Apply).</summary>
public sealed record CaseLayerDto(
    string Name,
    IReadOnlyList<CaseStepDto> Blocks);

/// <summary>One PDU / message in a multi-step network recipe (maps to sessionCommands).</summary>
public sealed record CaseSessionStepDto(
    string Name,
    IReadOnlyList<CaseStepDto> Blocks,
    bool ReadBanner = false,
    string? ExpectResponse = null,
    IReadOnlyList<CaseLayerDto>? Layers = null);

/// <summary>Saved Scare Floor recipe (editable block list — not the rendered seed bytes).</summary>
public sealed record CaseRecipeInfoDto(
    string Name,
    string? Description,
    int StepCount,
    DateTimeOffset UpdatedAt,
    string RelativePath,
    int SessionStepCount = 0,
    string? Kind = null);

public sealed record CaseRecipeDto(
    string Name,
    string? Description,
    IReadOnlyList<CaseStepDto> Steps,
    DateTimeOffset UpdatedAt,
    string? SuggestedSeedName = null,
    IReadOnlyList<CaseSessionStepDto>? SessionSteps = null,
    string? MutateStep = null,
    string? Kind = null);

public sealed record CaseSaveRecipeRequest(
    string Project,
    string Name,
    IReadOnlyList<CaseStepDto> Steps,
    string? Description = null,
    string? SuggestedSeedName = null,
    IReadOnlyList<CaseSessionStepDto>? SessionSteps = null,
    string? MutateStep = null,
    string? Kind = null);

public sealed record CaseSessionPreviewRequest(
    IReadOnlyList<CaseSessionStepDto> SessionSteps);

public sealed record CaseSessionStepPreviewDto(
    string Name,
    int Length,
    string HexPreview,
    string AsciiPreview,
    string HexFull,
    IReadOnlyList<string> DictionaryHints);

public sealed record CaseSessionPreviewDto(
    int StepCount,
    int TotalLength,
    IReadOnlyList<CaseSessionStepPreviewDto> Steps,
    IReadOnlyList<string> DictionaryHints,
    IReadOnlyList<string> Notes);

public sealed record CaseApplySessionRequest(
    string Project,
    string FlowName,
    IReadOnlyList<CaseSessionStepDto> SessionSteps,
    string MutateStep = "last",
    double SessionFlowBias = 0.5,
    bool PreferModels = false);

/// <summary>Split pasted capture text into session PDUs (blank line or --- separators).</summary>
public sealed record CaseFromStreamRequest(
    string Text,
    bool AsHex = false,
    string? Project = null,
    bool Apply = false,
    string? FlowName = null,
    string MutateStep = "last");

public sealed record CaseFromStreamDto(
    int StepCount,
    IReadOnlyList<CaseSessionStepDto> SessionSteps,
    IReadOnlyList<string> Notes,
    CaseSaveResultDto? Applied);

public sealed record CasePromoteRequest(
    string Project,
    string Name,
    IReadOnlyList<CaseStepDto> Steps,
    string? Description = null,
    string? SessionStepName = null);

public sealed record CasePromoteResultDto(
    bool Ok,
    string Message,
    string? RelativePath,
    string? AbsolutePath);

public sealed record CaseIdlRequest(
    string Project,
    string Name,
    string Idl,
    string? Description = null);

public sealed record CaseIdlResultDto(
    bool Ok,
    string Message,
    string? RelativePath,
    string? AbsolutePath,
    string? StructName,
    IReadOnlyList<string> Fields,
    IReadOnlyList<string> Notes);

public sealed record CasePackInfoDto(
    string Id,
    string Name,
    string? Description,
    string Kind,
    int SessionStepCount,
    IReadOnlyList<string> ProtocolRefs);

public sealed record SessionGraphSaveRequest(
    string ConfigPath,
    string Start,
    string? Mutate,
    IReadOnlyList<SessionGraphEdgeDto> Edges);

/// <summary>One browsable fuzzing recipe in the target catalog (file format / protocol / web).</summary>
public sealed record RecipeCatalogEntryDto(
    string Id,
    string Name,
    string Category,
    string Kind,          // file | tcp | udp | http
    string Description,
    IReadOnlyList<string> Tags,
    int? Port,
    string? Extension,
    IReadOnlyList<string> Mutators,
    int DictionaryCount);

/// <summary>Full catalog entry incl. a seed preview + dictionary (for detail view / instantiate).</summary>
public sealed record RecipeCatalogDetailDto(
    RecipeCatalogEntryDto Entry,
    string SeedHexPreview,
    int SeedLength,
    IReadOnlyList<string> Dictionary);

/// <summary>Create a working project from a catalog recipe.</summary>
public sealed record RecipeInstantiateRequest(
    string Id,
    string? Name = null,
    bool LocalFolder = true);
