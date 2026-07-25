namespace Randall.Contracts;

public sealed record RoadmapItemDto(string Id, string Title, bool Done, string? Note);

public sealed record RoadmapPhaseDto(
    int Phase,
    string Title,
    string Status,
    IReadOnlyList<RoadmapItemDto> Items);

public sealed record TargetProfileDto(
    string Name,
    string Kind,
    string Description,
    string ConfigPath);

public sealed record CrashSummaryDto(
    Guid Id,
    string Project,
    int Iteration,
    string Mutator,
    string InputHash,
    string InputPath,
    string? MiniDumpPath,
    string? TargetExitCode,
    string? TriageTag,
    string? SidecarPath,
    string? RunId,
    DateTimeOffset ObservedAt,
    string? CrashClass = null,
    string? Severity = null,
    string? FaultAddress = null,
    string? ExceptionHint = null,
    string? ClusterKey = null,
    /// <summary>True when triage thinks EIP/RIP / fault PC looks attacker-controlled (ASCII pattern, non-image, etc.).</summary>
    bool IpLooksControlled = false,
    /// <summary>One-line static map when Ghidra analysis or PE exports resolve the fault PC.</summary>
    string? StaticFunctionSummary = null,
    /// <summary>Unified scream rank for Investigation sorting (0+).</summary>
    int ScreamScore = 0,
    /// <summary>0–100 novelty from cluster + coverage + oracle signal.</summary>
    int Novelty = 0,
    /// <summary>Randall oracle score total when known.</summary>
    int? OracleScoreTotal = null,
    /// <summary>How many crashes share this cluster key in the project.</summary>
    int SeenCount = 0,
    /// <summary>Fused RIP + function + oracle + frontier one-liner for canister rack tooltips.</summary>
    string? CanisterContext = null,
    /// <summary>Primary normalized fault kind when intelligence is computed.</summary>
    string? PrimaryFaultKind = null,
    /// <summary>Primary fault summary for list / Investigation chips.</summary>
    string? PrimaryFaultSummary = null,
    /// <summary>Primary fault confidence 0–1 when known.</summary>
    double? PrimaryFaultConfidence = null);

public sealed record CdbTriageDto(
    bool Ok,
    string? ExploitableClassification,
    string? ExploitableDescription,
    string? AnalyzeTextPath,
    string? ExploitableTextPath,
    string? TriageJsonPath,
    bool MsecAvailable,
    string? Error);

public sealed record CrashDetailDto(
    CrashSummaryDto Summary,
    int InputLength,
    string HexPreview,
    string AsciiPreview,
    CrashSidecarDto? Sidecar,
    CrashAnalysisDto? Analysis,
    CrashTriageDto? Triage = null,
    CdbTriageDto? CdbTriage = null,
    CrashIntelligenceDto? Intelligence = null);

public sealed record SessionGraphReportDto(
    string Project,
    bool HasGraph,
    bool Valid,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings,
    string Mermaid,
    string? Start,
    string? Mutate,
    IReadOnlyList<SessionGraphEdgeDto> Edges,
    IReadOnlyList<string> Commands,
    string YamlSnippet);

public sealed record SessionGraphEdgeDto(string From, string When, string To);

public sealed record CrashClusterDto(
    string ClusterId,
    string Project,
    int Count,
    Guid RepresentativeId,
    string RepresentativeHash,
    string RepresentativeMutator,
    int LengthBucket,
    string? CrashClass = null,
    string? Severity = null,
    string? ExceptionHint = null,
    string? FaultAddress = null);

/// <summary>
/// One preflight check. <c>Platform</c> is a <see cref="PlatformScope"/> value
/// (<c>windows</c>/<c>linux</c>/<c>cross</c>) so the UI can show only OS-relevant rows.
/// </summary>
public sealed record DoctorCheckDto(string Id, string Status, string Message, string Platform = "cross");

public sealed record DoctorReportDto(
    string Project,
    bool Ready,
    IReadOnlyList<DoctorCheckDto> Checks,
    string Platform = "cross",
    string HostPlatform = "cross");
