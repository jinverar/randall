namespace Randall.Infrastructure;

using Randall.Contracts;

/// <summary>Leg 5 — Scream: bucket duplicate crashes for triage (AFL-style crash hashing).</summary>
public static class CrashCluster
{
    public static IReadOnlyList<CrashClusterSummary> Build(IEnumerable<CrashSummaryDto> crashes)
    {
        var groups = crashes
            .GroupBy(c => (c.Project, Bucket: c.InputHash[..Math.Min(8, c.InputHash.Length)], LengthBucket: LengthBucket(c)))
            .Select(g =>
            {
                var rep = g.OrderByDescending(c => c.ObservedAt).First();
                return new CrashClusterSummary(
                    $"{g.Key.Project}:{g.Key.Bucket}:{g.Key.LengthBucket}",
                    g.Key.Project,
                    g.Count(),
                    rep.Id,
                    rep.InputHash,
                    rep.Mutator,
                    g.Key.LengthBucket);
            })
            .OrderByDescending(c => c.Count)
            .ThenBy(c => c.Project)
            .ToList();
        return groups;
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
}

public sealed record CrashClusterSummary(
    string ClusterId,
    string Project,
    int Count,
    Guid RepresentativeId,
    string RepresentativeHash,
    string RepresentativeMutator,
    int LengthBucket);
