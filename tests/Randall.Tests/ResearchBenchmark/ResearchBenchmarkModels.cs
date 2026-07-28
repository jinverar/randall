using Randall.Contracts;

namespace Randall.Tests.ResearchBenchmark;

/// <summary>Expected envelope for one teaching-bug fixture.</summary>
public sealed record ResearchBenchmarkEnvelope(
    string FixtureId,
    string Family,
    bool Stub,
    bool ExpectCrashDetection,
    DebuggerAccessKind? ExpectedAccess = null,
    DebuggerAddressClass? ExpectedAddressClass = null,
    string? ExpectedPcContains = null,
    IReadOnlyList<RootCauseCategory>? AllowedRootFamilies = null,
    ResearchMaturity MaxMaturityWithoutPromotion = ResearchMaturity.R4,
    bool AllowR5Plus = false,
    string? Notes = null);

/// <summary>One row of the accuracy scorecard.</summary>
public sealed record ResearchBenchmarkScorecard(
    string FixtureId,
    string Family,
    bool Stub,
    bool CrashDetected,
    bool ClassificationOk,
    bool PcOk,
    bool RootCauseFamilyOk,
    bool AttributionHonest,
    ResearchMaturity ObservedMaturity,
    bool PrimitiveLevelOk,
    bool UnsupportedR5Plus,
    bool FalseConfidentClaims,
    string Summary,
    IReadOnlyList<string> Notes);

/// <summary>Rollup across fixtures.</summary>
public sealed record ResearchBenchmarkReport(
    int LiveCount,
    int StubCount,
    int PassedLive,
    IReadOnlyList<ResearchBenchmarkScorecard> Cards);
