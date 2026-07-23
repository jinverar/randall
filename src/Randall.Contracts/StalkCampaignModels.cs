namespace Randall.Contracts;

/// <summary>Named coverage layer — baseline, fuzzed, fuzzier, crash-N, …</summary>
public sealed record StalkLayerDto(
    string Id,
    string Project,
    string Tag,
    string Label,
    string ColorHex,
    DateTimeOffset CreatedAt,
    int BlockCount,
    string? SourcePath,
    string? CrashId,
    string? Notes,
    string? MiniTimelineDir = null,
    string? MiniTimelineSummary = null);

public sealed record StalkBlockHitDto(
    string Address,
    string Module,
    string Kind, // baseline | shared | novel | crash
    string? FirstLayerId,
    string? FirstLayerTag,
    IReadOnlyList<string> LayerIds);

public sealed record StalkCompareDto(
    string Project,
    IReadOnlyList<string> LayerIds,
    int UnionBlocks,
    int SharedBlocks,
    IReadOnlyList<StalkLayerDeltaDto> Deltas,
    IReadOnlyList<StalkBlockHitDto> Blocks);

public sealed record StalkLayerDeltaDto(
    string LayerId,
    string Tag,
    int UniqueBlocks,
    int NewVsPrevious);

public sealed record StalkCampaignDto(
    string Project,
    IReadOnlyList<StalkLayerDto> Layers,
    StalkCompareDto? Compare);

public sealed record StalkLayerCreateRequest(
    string Project,
    string Tag,
    string? Label,
    string? ColorHex,
    string? DrcovPath,
    string? EdgesPath,
    string? CrashId,
    string? Notes,
    /// <summary>When true, capture mini-timeline for this layer. When null, auto for all stalk tags if project enables miniTimeline / miniTimelineOnStalk.</summary>
    bool? MiniTimeline = null,
    int? MiniTimelineWindowSeconds = null);

public sealed record StalkLayerFromCrashRequest(
    string CrashId,
    string? Tag = null,
    string? Label = null);

public sealed record StalkLayerFromCorpusRequest(
    string Project,
    string? Tag = null,
    string? Label = null,
    bool? MiniTimeline = null);

public sealed record StalkExportRequest(
    string Project,
    IReadOnlyList<string> LayerIds,
    string Format, // idc | ghidra | edges
    string? OutputDir);

public sealed record StalkExportResultDto(
    string Format,
    string OutputPath,
    int BlockCount,
    IReadOnlyList<string> Files);

public sealed record StalkTimelineLayerStatsDto(
    string LayerId,
    string Tag,
    string Label,
    bool HasTimeline,
    string? SummaryLine,
    int EvtxRows,
    int MftRows,
    int PrefetchRows,
    int AmcacheRows,
    int AppCompatRows,
    int ProcmonRows,
    int WerCopied,
    int FingerprintCount);

public sealed record StalkTimelinePairDeltaDto(
    string FromLayerId,
    string FromTag,
    string ToLayerId,
    string ToTag,
    int Shared,
    int OnlyInFrom,
    int OnlyInTo,
    IReadOnlyList<string> SampleOnlyInTo,
    IReadOnlyList<string> SampleOnlyInFrom);

/// <summary>Host mini-timeline compare across stalk layers (baseline → fuzzed → fuzzier → …).</summary>
public sealed record StalkTimelineCompareDto(
    string Project,
    IReadOnlyList<string> LayerIds,
    IReadOnlyList<StalkTimelineLayerStatsDto> Layers,
    IReadOnlyList<StalkTimelinePairDeltaDto> Pairwise,
    string SummaryLine);

public sealed record StalkToolLinkDto(
    string Id,
    string Name,
    string Status, // ready | missing | planned
    string Description,
    string? CommandHint);

public sealed record StalkWorkspaceDto(
    string Project,
    StalkCampaignDto Campaign,
    IReadOnlyList<StalkToolLinkDto> Tools,
    string WorkflowHint);
