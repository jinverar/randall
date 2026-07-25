using Randall.Contracts;
using Randall.Infrastructure.Oracles;

namespace Randall.Infrastructure;

/// <summary>Builds formal scream intelligence from catalog rows, triage, sidecars, and cluster stats.</summary>
public static class CrashIntelligenceBuilder
{
    public static CrashIntelligenceDto Build(
        CrashSummaryDto summary,
        CrashTriageDto? triage,
        CrashSidecarDto? sidecar,
        int inputLength,
        IReadOnlyList<CrashSummaryDto> projectCrashes,
        CrashAnalysisDto? analysis = null,
        CdbTriageDto? cdb = null,
        bool pageHeapEnabled = false,
        string? rppTag = null)
    {
        var clusterKey = triage?.ClusterKey ?? summary.ClusterKey;
        var clusterMembers = string.IsNullOrWhiteSpace(clusterKey)
            ? [summary]
            : projectCrashes
                .Where(c => string.Equals(c.ClusterKey, clusterKey, StringComparison.OrdinalIgnoreCase))
                .ToList();
        if (clusterMembers.Count == 0)
            clusterMembers = [summary];

        var seenCount = clusterMembers.Count;
        var firstSeen = clusterMembers.Min(c => c.ObservedAt);

        var oracleScore = sidecar?.RandallScore;
        if (oracleScore is null or { Total: 0 } && sidecar is not null)
        {
            oracleScore = OracleScorer.CrashScore(
                sidecar.ExceptionHint ?? sidecar.TargetDetail,
                sidecar.NewEdgesAtCrash);
        }

        var coverageDelta = sidecar?.NewEdgesAtCrash;
        var function = triage?.StaticFunction is not null
            ? CrashStaticFunctionMapper.FormatOneLine(triage.StaticFunction)
            : summary.StaticFunctionSummary;
        var offset = triage?.PatternDepthBytes;
        var severity = (triage?.Severity ?? summary.Severity ?? "low").ToLowerInvariant();
        var novelty = ComputeNovelty(seenCount, coverageDelta, oracleScore?.Total);
        var reproducible = ReproLooksReady(summary, sidecar);
        var minimized = IsMinimized(summary, clusterMembers, inputLength);
        var lineage = BuildLineage(sidecar);
        var screamScore = ComputeScreamScore(severity, novelty, oracleScore?.Total, seenCount, triage);
        var faultSignals = FaultSignalMapper.FromCrash(
            triage, analysis, cdb, sidecar, pageHeapEnabled, rppTag ?? summary.TriageTag);
        var primaryFault = FaultSignalMapper.Primary(faultSignals);
        var frontierHint = BuildFrontierHint(summary.Project, triage, CrashCatalog.FindRepoRoot());
        var canisterContext = BuildCanisterContext(triage, function, oracleScore, frontierHint);

        return new CrashIntelligenceDto(
            severity,
            novelty,
            clusterKey,
            seenCount,
            coverageDelta,
            function,
            offset,
            oracleScore,
            reproducible,
            minimized,
            firstSeen,
            seenCount,
            lineage,
            screamScore,
            primaryFault,
            faultSignals,
            canisterContext,
            frontierHint);
    }

    public static CrashSummaryDto WithListIntelligence(
        CrashSummaryDto summary,
        CrashIntelligenceDto intelligence) =>
        summary with
        {
            ScreamScore = intelligence.ScreamScore,
            Novelty = intelligence.Novelty,
            OracleScoreTotal = intelligence.OracleScore?.Total,
            SeenCount = intelligence.SeenCount,
            CanisterContext = intelligence.CanisterContext,
        };

    private static string? BuildFrontierHint(string project, CrashTriageDto? triage, string? repoRoot)
    {
        var frontier = FrontierEngine.TryLoad(project, repoRoot);
        var fn = triage?.StaticFunction?.FunctionName;
        var near = GhidraCallGraphHelper.FindNearestFrontier(fn, frontier);
        if (near is null)
            return null;

        var label = string.IsNullOrWhiteSpace(near.FunctionName)
            ? near.ToAddress
            : $"{near.FunctionName}→{near.ToAddress}";
        return near.Kind switch
        {
            "session-fork" => $"session fork near {label} [{near.Score}]",
            "edge-gap" => $"edge gap near {label} [{near.Score}]",
            _ => $"gray door {label} [{near.Score}]",
        };
    }

    private static string? BuildCanisterContext(
        CrashTriageDto? triage,
        string? function,
        OracleScore? oracleScore,
        string? frontierHint)
    {
        var parts = new List<string>();
        var rip = triage?.Rip ?? triage?.StaticFunction?.PcAddress;
        if (!string.IsNullOrWhiteSpace(rip))
            parts.Add($"RIP {rip}");
        if (!string.IsNullOrWhiteSpace(function))
            parts.Add(function);
        if (oracleScore is { Total: > 0 })
            parts.Add($"oracle {oracleScore.Total}");
        if (!string.IsNullOrWhiteSpace(frontierHint))
            parts.Add(frontierHint);
        return parts.Count == 0 ? null : string.Join(" · ", parts);
    }

    private static int ComputeNovelty(int seenCount, int? coverageDelta, int? oracleTotal)
    {
        var baseScore = seenCount switch
        {
            <= 1 => 88,
            <= 3 => 62,
            <= 10 => 38,
            _ => 14,
        };

        if (coverageDelta is > 0)
            baseScore += Math.Min(12, coverageDelta.Value * 4);

        if (oracleTotal is > 0)
            baseScore += Math.Min(20, oracleTotal.Value / 5);

        return Math.Clamp(baseScore, 0, 100);
    }

    private static int ComputeScreamScore(
        string severity,
        int novelty,
        int? oracleTotal,
        int seenCount,
        CrashTriageDto? triage)
    {
        var sev = severity switch
        {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        };

        var uniqueBonus = seenCount <= 1 ? 20 : seenCount <= 3 ? 10 : 0;
        var ipBonus = triage?.IpLooksControlled == true ? 12 : 0;
        var oracleBonus = oracleTotal is > 0 ? Math.Min(25, oracleTotal.Value / 4) : 0;
        return sev * 12 + novelty / 2 + uniqueBonus + ipBonus + oracleBonus;
    }

    private static bool ReproLooksReady(CrashSummaryDto summary, CrashSidecarDto? sidecar)
    {
        if (sidecar is not null)
            return true;

        if (string.IsNullOrWhiteSpace(summary.InputPath))
            return false;
        try
        {
            return File.Exists(summary.InputPath);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsMinimized(
        CrashSummaryDto summary,
        IReadOnlyList<CrashSummaryDto> clusterMembers,
        int inputLength)
    {
        if (inputLength <= 0)
            return false;

        foreach (var member in clusterMembers)
        {
            if (member.Id == summary.Id)
                continue;
            if (!File.Exists(member.InputPath))
                continue;
            try
            {
                var len = (int)new FileInfo(member.InputPath).Length;
                if (len < inputLength)
                    return false;
            }
            catch
            {
                /* ignore */
            }
        }

        return true;
    }

    private static CrashLineageDto? BuildLineage(CrashSidecarDto? sidecar) =>
        CrashLineageResolver.Resolve(sidecar);
}
