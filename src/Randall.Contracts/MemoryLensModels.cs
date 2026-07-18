namespace Randall.Contracts;

/// <summary>Human-readable memory/heap lens for a crash or live PID (Target Runtime Phase D/F).</summary>
public sealed record MemoryLensReportDto(
    bool Ok,
    string? DumpPath,
    int? Pid,
    string Confidence,
    IReadOnlyList<string> SummaryLines,
    MemoryLensFaultDto? Fault,
    IReadOnlyList<MemoryLensRegionDto> Regions,
    IReadOnlyList<MemoryLensPatternHitDto> PatternHits,
    IReadOnlyList<MemoryLensLinkHintDto> LinkHints,
    MemoryLensNeighborhoodDto? Neighborhood,
    string? Error,
    IReadOnlyList<string>? HeapSummaryLines = null,
    bool PageHeapLikely = false,
    string? HeapBackend = null);

public sealed record MemoryLensFaultDto(
    string? ExceptionCode,
    string? ExceptionHint,
    string? FaultAddress,
    string? AccessType,
    string? FaultModule);

public sealed record MemoryLensRegionDto(
    string BaseAddress,
    string Size,
    string Protect,
    string Kind,
    string? Label);

public sealed record MemoryLensPatternHitDto(
    string Where,
    string Value,
    string PatternName,
    string Hint,
    string Confidence);

public sealed record MemoryLensLinkHintDto(
    string Where,
    string Flink,
    string Blink,
    string Note,
    string Confidence);

public sealed record MemoryLensNeighborhoodDto(
    string BaseAddress,
    int Length,
    string HexPreview,
    string AsciiPreview,
    IReadOnlyList<string> Annotations);
