namespace Randall.Contracts;

/// <summary>
/// Static target map exported from Ghidra (or validated after Script Manager export).
/// Consumed by stalk/oracle for fuzz-priority hints. See docs/GHIDRA_INTEGRATION.md.
/// </summary>
public sealed record RandallAnalysisDocument(
    string Version,
    string Binary,
    string? BinarySha256,
    string ImageBase,
    string ExportedAt,
    string? Exporter,
    IReadOnlyList<RandallAnalysisFunctionDto> Functions,
    IReadOnlyList<RandallAnalysisImportDto> Imports,
    IReadOnlyList<RandallAnalysisExportDto> Exports,
    IReadOnlyList<RandallAnalysisSinkDto> Sinks,
    IReadOnlyList<RandallAnalysisXrefDto> Xrefs);

public sealed record RandallAnalysisFunctionDto(
    string Name,
    string Address,
    int Size,
    int BasicBlockCount,
    int Complexity,
    int CallerCount,
    int CalleeCount,
    bool InputReachable,
    bool HasDangerousCalls,
    IReadOnlyList<string> DangerousCalls,
    int FuzzPriority);

public sealed record RandallAnalysisImportDto(
    string Library,
    string Name,
    string Address);

public sealed record RandallAnalysisExportDto(
    string Name,
    string Address);

public sealed record RandallAnalysisSinkDto(
    string Name,
    string Address,
    string Kind,
    int Risk,
    IReadOnlyList<string> Callers);

public sealed record RandallAnalysisXrefDto(
    string FromFunction,
    string FromAddress,
    string ToSymbol,
    string ToAddress,
    string RefKind);

public sealed record GhidraAnalyzeResultDto(
    string Project,
    string BinaryPath,
    string OutputPath,
    bool FromHeadless,
    int FunctionCount,
    int SinkCount,
    IReadOnlyList<RandallAnalysisFunctionDto> TopPriorities,
    string? Detail);
