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
    IReadOnlyList<RandallAnalysisXrefDto> Xrefs,
    IReadOnlyList<RandallAnalysisCallEdgeDto> CallGraph = null!,
    RandallAnalysisCoverageSummaryDto? CoverageSummary = null,
    IReadOnlyList<RandallAnalysisChangedFunctionDto>? ChangedFunctions = null,
    IReadOnlyList<RandallAnalysisBsimMatchDto>? BsimMatches = null,
    RandallAnalysisDiffMetaDto? DiffMeta = null);

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
    int FuzzPriority,
    RandallAnalysisFunctionCfgDto? Cfg = null,
    int CoveredBlockCount = 0,
    int UncoveredBlockCount = 0,
    double? CoverageFraction = null,
    int UncoveredDistance = 0,
    bool IsFullyCovered = false);

public sealed record RandallAnalysisFunctionCfgDto(
    IReadOnlyList<RandallAnalysisBasicBlockDto> Blocks);

public sealed record RandallAnalysisBasicBlockDto(
    string Address,
    int Size,
    IReadOnlyList<string> Successors,
    IReadOnlyList<string> Predecessors);

public sealed record RandallAnalysisCallEdgeDto(
    string Caller,
    string Callee,
    string CallSite);

public sealed record RandallAnalysisCoverageSummaryDto(
    int TotalBlocks,
    int CoveredBlocks,
    int UncoveredBlocks,
    double CoverageFraction,
    int FunctionsFullyCovered,
    int FunctionsWithGaps,
    IReadOnlyList<string> TopUncoveredTargets);

/// <summary>
/// Heuristic function delta from comparing two <c>randall-analysis.json</c> exports (json-merge)
/// or optional BinDiff companion input. Populated only when a baseline analysis is supplied.
/// </summary>
public sealed record RandallAnalysisChangedFunctionDto(
    string Name,
    string Address,
    string ChangeKind,
    string? BaselineName,
    string? BaselineAddress,
    int SizeDelta,
    int ComplexityDelta,
    int BasicBlockCountDelta,
    int FuzzPriorityDelta,
    double ChangeScore);

/// <summary>
/// Optional BSim similarity row (manual Ghidra export or future headless hook).
/// </summary>
public sealed record RandallAnalysisBsimMatchDto(
    string QueryFunction,
    string QueryAddress,
    string MatchFunction,
    string MatchAddress,
    double Similarity,
    string? MatchBinary,
    string Source);

public sealed record RandallAnalysisDiffMetaDto(
    string? BaselinePath,
    string? BaselineBinary,
    string? BaselineBinarySha256,
    string ComparedAt,
    string Source);

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

/// <summary>
/// Maps a crash RIP/fault PC to a static function + offset (Ghidra map or PE heuristics).
/// </summary>
public sealed record StaticFunctionMappingDto(
    string PcSource,
    string PcAddress,
    string FunctionName,
    string Offset,
    string Source,
    string? ModuleRva = null,
    string? InstructionHint = null,
    int? FuzzPriority = null);
