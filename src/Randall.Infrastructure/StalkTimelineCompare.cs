using System.Security.Cryptography;
using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Diff host mini-timelines across stalk layers (baseline → fuzzed → fuzzier → …).
/// Soft when a layer has no timeline — still reports stats gaps.
/// </summary>
public static class StalkTimelineCompare
{
    public static StalkTimelineCompareDto Compare(
        string project,
        IReadOnlyList<string>? layerIds = null,
        string? repoRoot = null,
        int sampleLimit = 12)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var stalkDir = StalkCampaignStore.ProjectDir(project, repoRoot);
        var layers = StalkCampaignStore.ListLayers(project, repoRoot)
            .Where(l => layerIds is null || layerIds.Count == 0 ||
                        layerIds.Contains(l.Id, StringComparer.OrdinalIgnoreCase))
            .OrderBy(l => l.CreatedAt)
            .ToList();

        var stats = new List<StalkTimelineLayerStatsDto>();
        var prints = new List<(StalkLayerDto Layer, HashSet<string> Prints)>();

        foreach (var layer in layers)
        {
            var key = $"layer-{layer.Id}";
            var summary = MiniTimelineCapture.TryRead(stalkDir, key);
            var set = LoadFingerprints(stalkDir, key);
            prints.Add((layer, set));
            stats.Add(new StalkTimelineLayerStatsDto(
                layer.Id,
                layer.Tag,
                layer.Label,
                summary is not null || set.Count > 0,
                summary?.SummaryLine ?? layer.MiniTimelineSummary,
                summary?.EvtxRows ?? 0,
                summary?.MftRows ?? 0,
                summary?.PrefetchRows ?? 0,
                summary?.AmcacheRows ?? 0,
                summary?.AppCompatRows ?? 0,
                summary?.ProcmonRows ?? 0,
                summary?.WerCopied ?? 0,
                set.Count));
        }

        var pairwise = new List<StalkTimelinePairDeltaDto>();
        for (var i = 1; i < prints.Count; i++)
        {
            var from = prints[i - 1];
            var to = prints[i];
            var shared = from.Prints.Intersect(to.Prints, StringComparer.Ordinal).Count();
            var onlyFrom = from.Prints.Except(to.Prints, StringComparer.Ordinal).ToList();
            var onlyTo = to.Prints.Except(from.Prints, StringComparer.Ordinal).ToList();
            pairwise.Add(new StalkTimelinePairDeltaDto(
                from.Layer.Id,
                from.Layer.Tag,
                to.Layer.Id,
                to.Layer.Tag,
                shared,
                onlyFrom.Count,
                onlyTo.Count,
                onlyTo.Take(sampleLimit).Select(Shorten).ToList(),
                onlyFrom.Take(sampleLimit).Select(Shorten).ToList()));
        }

        var withTl = stats.Count(s => s.HasTimeline);
        var novel = pairwise.Sum(p => p.OnlyInTo);
        var summaryLine = layers.Count == 0
            ? "no stalk layers"
            : withTl == 0
                ? $"{layers.Count} layer(s), no host mini-timelines yet — enable checkbox / fuzz.miniTimelineOnStalk"
                : $"{withTl}/{layers.Count} timelines · {pairwise.Count} pair(s) · +{novel} novel host row(s) vs previous";

        return new StalkTimelineCompareDto(
            project,
            layers.Select(l => l.Id).ToList(),
            stats,
            pairwise,
            summaryLine);
    }

    private static HashSet<string> LoadFingerprints(string stalkDir, string timelineKey)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        var dir = MiniTimelineCapture.TimelineDir(stalkDir, timelineKey);
        if (!Directory.Exists(dir))
            return set;

        var merged = Path.Combine(dir, "merged.csv");
        if (File.Exists(merged))
        {
            foreach (var line in File.ReadLines(merged).Skip(1))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                set.Add(Fingerprint(line));
            }

            return set;
        }

        foreach (var name in new[] { "evtx.csv", "mft.csv", "procmon.csv", "prefetch.csv", "amcache.csv", "appcompat.csv" })
        {
            var path = Path.Combine(dir, name);
            if (!File.Exists(path)) continue;
            var source = Path.GetFileNameWithoutExtension(name);
            foreach (var line in File.ReadLines(path).Skip(1))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                set.Add(Fingerprint(source + "," + line));
            }
        }

        return set;
    }

    private static string Fingerprint(string raw)
    {
        // Drop volatile time-of-day prefixes so the same op across runs can match when useful,
        // but keep enough of the row to distinguish events. Hash for stable compact set keys.
        var normalized = raw.Trim();
        if (normalized.Length > 400)
            normalized = normalized[..400];
        var bytes = Encoding.UTF8.GetBytes(normalized);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash)[..24] + "|" + (normalized.Length > 80 ? normalized[..80] : normalized);
    }

    private static string Shorten(string fingerprint)
    {
        var pipe = fingerprint.IndexOf('|');
        var body = pipe >= 0 && pipe + 1 < fingerprint.Length ? fingerprint[(pipe + 1)..] : fingerprint;
        return body.Length <= 160 ? body : body[..157] + "…";
    }
}
