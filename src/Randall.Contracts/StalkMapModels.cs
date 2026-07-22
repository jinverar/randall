namespace Randall.Contracts;

/// <summary>
/// In-Randall stalk map: coverage gaps enriched with PE/ELF strings, imports, and sections.
/// This is RE-for-fuzzing — not a decompiler.
/// </summary>
public sealed record StalkMapDto(
    string Project,
    string? BinaryPath,
    /// <summary>pe | elf | unknown | missing</summary>
    string Format,
    string Summary,
    StalkMissedReportDto Missed,
    IReadOnlyList<BinarySectionDto> Sections,
    IReadOnlyList<BinaryImportDto> InterestingImports,
    IReadOnlyList<BinaryStringDto> HotStrings,
    IReadOnlyList<StalkMapHotspotDto> Hotspots,
    IReadOnlyList<MissedFuzzIdeaDto> SurfaceIdeas);

public sealed record BinarySectionDto(
    string Name,
    string Rva,
    string Size,
    string Characteristics);

public sealed record BinaryImportDto(
    string Library,
    string Function,
    string? ThunkRva,
    bool Interesting);

public sealed record BinaryStringDto(
    string Rva,
    string Text,
    string Section);

public sealed record StalkMapHotspotDto(
    StalkMissedBlockDto Block,
    string? Section,
    IReadOnlyList<string> NearbyStrings,
    IReadOnlyList<string> NearbyImports,
    /// <summary>string-adjacent | import-adjacent | code | data | unknown</summary>
    string SurfaceKind,
    int BoostedScore);
