namespace Randall.Contracts;

/// <summary>
/// Wave 7 research package report stub — a teaching rollup of what to study next
/// for one crash or campaign. Research-only; never includes exploit payloads.
/// </summary>
public sealed record ResearchPackageItemDto(
    string Id,
    string Title,
    string Description,
    /// <summary>Suggested study order (1 = first).</summary>
    int Priority,
    IReadOnlyList<string> EvidenceRefs);

/// <summary>
/// Persisted as <c>{guid}_research_package.json</c> (per crash) or
/// <c>data/stalk/&lt;project&gt;/research_package_last.json</c> (campaign rollup).
/// </summary>
public sealed record ResearchPackageReportDto(
    bool Ok,
    string Project,
    Guid? CrashId,
    string Summary,
    IReadOnlyList<ResearchPackageItemDto> Packages,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN</summary>
    string Confidence,
    DateTimeOffset At,
    string? Error = null);
