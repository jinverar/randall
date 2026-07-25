using System.Globalization;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Overlays stalk/drcov coverage edges onto Ghidra static CFG and recomputes fuzz priorities.
/// </summary>
public static class GhidraCoverageOverlay
{
    public sealed record CoverageBlock(ulong Start, ulong Size);

    public static IReadOnlyList<CoverageBlock> LoadStalkCoverage(string project, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var blocks = new List<CoverageBlock>();

        foreach (var layer in StalkCampaignStore.ListLayers(project, repoRoot))
        {
            foreach (var edge in StalkCampaignStore.LoadEdges(project, layer.Id, repoRoot))
                TryAddEdge(edge, blocks);
        }

        var stalkDir = StalkCampaignStore.ProjectDir(project, repoRoot);
        foreach (var name in new[] { "coverage_edges.txt", "edges.txt" })
        {
            var path = Path.Combine(stalkDir, name);
            if (File.Exists(path))
            {
                foreach (var line in File.ReadLines(path))
                    TryAddEdge(line, blocks);
            }
        }

        var corpusEdges = Path.Combine(repoRoot, "data", "corpus", project, "edges.txt");
        if (File.Exists(corpusEdges))
        {
            foreach (var line in File.ReadLines(corpusEdges))
                TryAddEdge(line, blocks);
        }

        return blocks;
    }

    public static RandallAnalysisDocument Apply(
        RandallAnalysisDocument doc,
        string project,
        string? repoRoot = null)
    {
        var coverage = LoadStalkCoverage(project, repoRoot);
        if (coverage.Count == 0)
            return doc;

        if (!TryParseAddress(doc.ImageBase, out var imageBase))
            imageBase = 0;

        var totalBlocks = 0;
        var coveredBlocks = 0;
        var functionsFullyCovered = 0;
        var functionsWithGaps = 0;
        var enrichedFunctions = new List<RandallAnalysisFunctionDto>();

        foreach (var fn in doc.Functions)
        {
            var cfgBlocks = fn.Cfg?.Blocks ?? [];
            if (cfgBlocks.Count == 0)
            {
                enrichedFunctions.Add(fn);
                continue;
            }

            var blockStates = new List<(RandallAnalysisBasicBlockDto Block, bool Covered)>();
            foreach (var bb in cfgBlocks)
            {
                var covered = IsBlockCovered(bb, coverage, imageBase);
                blockStates.Add((bb, covered));
                totalBlocks++;
                if (covered)
                    coveredBlocks++;
            }

            var fnCovered = blockStates.Count(b => b.Covered);
            var fnUncovered = blockStates.Count - fnCovered;
            var fnFraction = blockStates.Count == 0 ? 1.0 : (double)fnCovered / blockStates.Count;
            var uncoveredDist = ComputeUncoveredDistance(blockStates);

            if (fnUncovered == 0)
                functionsFullyCovered++;
            else
                functionsWithGaps++;

            var staticPriority = fn.FuzzPriority > 0
                ? fn.FuzzPriority
                : GhidraAnalysisBridge.ComputeFuzzPriority(
                    fn.Complexity, fn.BasicBlockCount, fn.DangerousCalls, fn.InputReachable, fn.CallerCount);

            var maxSinkRisk = MaxSinkRisk(fn);
            var priority = ComputeCoverageAwareFuzzPriority(
                staticPriority, maxSinkRisk, fn.Complexity, uncoveredDist, fnFraction);

            enrichedFunctions.Add(fn with
            {
                FuzzPriority = priority,
                CoveredBlockCount = fnCovered,
                UncoveredBlockCount = fnUncovered,
                CoverageFraction = Math.Round(fnFraction, 4),
                UncoveredDistance = uncoveredDist,
                IsFullyCovered = fnUncovered == 0,
            });
        }

        var overallFraction = totalBlocks == 0 ? 0.0 : (double)coveredBlocks / totalBlocks;
        var topUncovered = enrichedFunctions
            .Where(f => f.UncoveredBlockCount > 0)
            .OrderByDescending(f => f.FuzzPriority)
            .ThenByDescending(f => f.UncoveredBlockCount)
            .Take(8)
            .Select(f => f.Name)
            .ToList();

        var summary = new RandallAnalysisCoverageSummaryDto(
            totalBlocks,
            coveredBlocks,
            totalBlocks - coveredBlocks,
            Math.Round(overallFraction, 4),
            functionsFullyCovered,
            functionsWithGaps,
            topUncovered);

        return doc with { Functions = enrichedFunctions, CoverageSummary = summary };
    }

    /// <summary>
    /// sinkRisk × complexity × uncoveredDistance / coverageFraction, normalized to 0–100.
    /// </summary>
    public static int ComputeCoverageAwareFuzzPriority(
        int staticPriority,
        int maxSinkRisk,
        int complexity,
        int uncoveredDistance,
        double coverageFraction)
    {
        var frac = Math.Clamp(coverageFraction, 0.01, 1.0);
        var distFactor = Math.Clamp(uncoveredDistance / 10.0, 0.1, 10.0);
        var complexityFactor = Math.Min(complexity, 100) / 100.0;
        var sinkFactor = Math.Clamp(maxSinkRisk, 1, 100) / 100.0;

        var raw = sinkFactor * complexityFactor * distFactor / frac * 100.0;
        var coverageScore = Math.Clamp((int)Math.Round(raw), 0, 100);
        return Math.Clamp(Math.Max(staticPriority, (staticPriority + coverageScore * 2) / 3), 0, 100);
    }

    public static int ComputeUncoveredDistance(
        IReadOnlyList<(RandallAnalysisBasicBlockDto Block, bool Covered)> blockStates)
    {
        if (blockStates.Count == 0)
            return 0;

        var addrToIndex = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < blockStates.Count; i++)
            addrToIndex[blockStates[i].Block.Address] = i;

        var adj = new List<int>[blockStates.Count];
        for (var i = 0; i < blockStates.Count; i++)
        {
            adj[i] = [];
            foreach (var succ in blockStates[i].Block.Successors)
            {
                if (addrToIndex.TryGetValue(succ, out var j))
                    adj[i].Add(j);
            }
        }

        var uncovered = new List<int>();
        for (var i = 0; i < blockStates.Count; i++)
        {
            if (!blockStates[i].Covered)
                uncovered.Add(i);
        }

        if (uncovered.Count == 0)
            return 0;
        if (uncovered.Count == blockStates.Count)
            return Math.Min(blockStates.Count, 99);

        var dist = Enumerable.Repeat(int.MaxValue, blockStates.Count).ToArray();
        var queue = new Queue<int>();
        for (var i = 0; i < blockStates.Count; i++)
        {
            if (blockStates[i].Covered)
            {
                dist[i] = 0;
                queue.Enqueue(i);
            }
        }

        while (queue.Count > 0)
        {
            var u = queue.Dequeue();
            foreach (var v in adj[u])
            {
                if (dist[v] != int.MaxValue)
                    continue;
                dist[v] = dist[u] + 1;
                queue.Enqueue(v);
            }
        }

        var minUncovered = uncovered.Min(i => dist[i] == int.MaxValue ? blockStates.Count : dist[i]);
        return minUncovered == int.MaxValue ? blockStates.Count : minUncovered;
    }

    public static bool IsBlockCovered(
        RandallAnalysisBasicBlockDto block,
        IReadOnlyList<CoverageBlock> coverage,
        ulong imageBase)
    {
        if (!TryParseAddress(block.Address, out var bbStart))
            return false;

        var bbSize = (ulong)Math.Max(1, block.Size);
        var bbEnd = bbStart + bbSize;
        var bbRva = bbStart >= imageBase ? bbStart - imageBase : bbStart;

        foreach (var cov in coverage)
        {
            var covEnd = cov.Start + cov.Size;
            if (RangesOverlap(bbRva, bbRva + bbSize, cov.Start, covEnd))
                return true;
            if (imageBase > 0 && RangesOverlap(bbStart, bbEnd, imageBase + cov.Start, imageBase + covEnd))
                return true;
        }

        return false;
    }

    public static bool TryParseCoverageEdge(string edge, out CoverageBlock block)
    {
        block = new CoverageBlock(0, 0);
        if (string.IsNullOrWhiteSpace(edge))
            return false;

        var parts = edge.Trim().Split(':');
        if (parts.Length < 3)
            return false;

        if (!TryParseAddress(parts[1], out var start))
            return false;
        if (!ulong.TryParse(parts[2].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var size))
            return false;

        block = new CoverageBlock(start, Math.Max(1, size));
        return true;
    }

    public static bool TryParseAddress(string addr, out ulong value)
    {
        value = 0;
        var s = addr.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            s = s[2..];
        return ulong.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
    }

    private static void TryAddEdge(string edge, List<CoverageBlock> blocks)
    {
        if (TryParseCoverageEdge(edge, out var block))
            blocks.Add(block);
    }

    private static bool RangesOverlap(ulong aStart, ulong aEnd, ulong bStart, ulong bEnd) =>
        aStart < bEnd && bStart < aEnd;

    private static int MaxSinkRisk(RandallAnalysisFunctionDto fn)
    {
        if (fn.DangerousCalls.Count == 0)
            return fn.InputReachable ? 35 : 25;

        return fn.DangerousCalls.Max(GhidraAnalysisBridge.SinkRisk);
    }
}
