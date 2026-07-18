namespace Randall.Infrastructure;

using Randall.Contracts;

/// <summary>Leg 5 — Scream: bucket crashes by fault signature for triage.</summary>
public static class CrashCluster
{
    public static IReadOnlyList<CrashClusterSummary> Build(
        IEnumerable<CrashSummaryDto> crashes,
        string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot();
        var enriched = new List<(CrashSummaryDto Crash, CrashTriageDto Triage)>();
        foreach (var c in crashes)
        {
            var triage = LoadTriage(c, repoRoot);
            enriched.Add((c, triage));
        }

        return enriched
            .GroupBy(x => x.Triage.ClusterKey, StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                var rep = g.OrderByDescending(x => x.Crash.ObservedAt).First();
                var lenBucket = LengthBucket(rep.Crash);
                return new CrashClusterSummary(
                    g.Key,
                    rep.Crash.Project,
                    g.Count(),
                    rep.Crash.Id,
                    rep.Crash.InputHash,
                    rep.Crash.Mutator,
                    lenBucket,
                    rep.Triage.Class,
                    rep.Triage.Severity,
                    rep.Triage.ExceptionHint,
                    rep.Triage.FaultAddress);
            })
            .OrderByDescending(c => SeverityRank(c.Severity))
            .ThenByDescending(c => c.Count)
            .ThenBy(c => c.Project)
            .ToList();
    }

    private static CrashTriageDto LoadTriage(CrashSummaryDto crash, string? repoRoot)
    {
        CrashAnalysisDto? analysis = null;
        try
        {
            var crashesDir = Path.GetDirectoryName(crash.InputPath);
            if (crashesDir is not null)
            {
                var analysisPath = CrashAnalysisWriter.AnalysisPathFor(crashesDir, crash.Id);
                analysis = CrashAnalysisWriter.TryRead(analysisPath)
                    ?? (crash.MiniDumpPath is not null
                        ? CrashAnalysisWriter.AnalyzeDump(crash.MiniDumpPath)
                        : null);
            }
        }
        catch
        {
            /* best-effort */
        }

        var sidecar = CrashSidecarWriter.TryRead(crash.SidecarPath);
        return CrashTriage.Classify(analysis, sidecar, crash);
    }

    private static int LengthBucket(CrashSummaryDto crash)
    {
        if (!File.Exists(crash.InputPath))
            return 0;
        try
        {
            var len = (int)new FileInfo(crash.InputPath).Length;
            return len / 64;
        }
        catch
        {
            return 0;
        }
    }

    private static int SeverityRank(string? severity) => severity switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    };
}

public sealed record CrashClusterSummary(
    string ClusterId,
    string Project,
    int Count,
    Guid RepresentativeId,
    string RepresentativeHash,
    string RepresentativeMutator,
    int LengthBucket,
    string? CrashClass,
    string? Severity,
    string? ExceptionHint,
    string? FaultAddress);
