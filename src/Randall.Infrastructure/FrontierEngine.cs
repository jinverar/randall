using System.Globalization;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Scores unexplored stalk branches (gray doors) from Ghidra CFG + coverage edges,
/// with session-graph fallback when static analysis is absent.
/// FrontierScore ≈ CFGDistance × Rarity × UnseenSuccessorCount × SinkProximity.
/// </summary>
public static class FrontierEngine
{
    public const string FileName = "frontier.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
    };

    public static string FrontierPath(string project, string? repoRoot = null) =>
        Path.Combine(StalkCampaignStore.ProjectDir(project, repoRoot), FileName);

    public static FrontierReportDto Score(
        string project,
        string? repoRoot = null,
        int limit = 40,
        FuzzSessionStatusDto? liveStatus = null,
        bool persist = true)
    {
        if (string.IsNullOrWhiteSpace(project))
            throw new ArgumentException("project required");

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        limit = Math.Clamp(limit, 1, 200);

        var coverage = GhidraCoverageOverlay.LoadStalkCoverage(project, repoRoot);
        var layers = StalkCampaignStore.ListLayers(project, repoRoot);
        var analysis = GhidraAnalysisBridge.TryLoad(project, repoRoot);

        var frontiers = new List<FrontierBranchDto>();
        if (analysis is not null)
            frontiers.AddRange(ScoreCfgBranches(analysis, coverage, layers, project, repoRoot));

        frontiers.AddRange(ScoreSessionForks(project, liveStatus));
        if (analysis is null && coverage.Count > 0)
            frontiers.AddRange(ScoreEdgeGaps(project, repoRoot, limit));

        frontiers = frontiers
            .GroupBy(f => f.EdgeKey, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(x => x.Score).First())
            .OrderByDescending(f => f.Score)
            .ThenBy(f => f.ToAddress, StringComparer.OrdinalIgnoreCase)
            .Take(limit)
            .ToList();

        var mode = ResolveMode(analysis, frontiers);
        var summary = BuildSummary(frontiers, coverage.Count, analysis);
        var report = new FrontierReportDto(
            project,
            DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture),
            mode,
            summary,
            coverage.Count,
            frontiers.Count,
            analysis is null ? null : GhidraAnalysisBridge.AnalysisPath(project, repoRoot),
            frontiers,
            "Run randall stalk frontier -p " + project + " after new layers; bias seeds toward top gray doors.");

        if (persist)
        {
            Save(report, repoRoot);
            try { TargetIntelligenceWriteBack.OnFrontierSaved(report, repoRoot); }
            catch { /* write-back must not break frontier save */ }
        }

        return ScareDoorProgressStore.EnrichReport(report, repoRoot);
    }

    public static FrontierReportDto? TryLoad(string project, string? repoRoot = null)
    {
        var path = FrontierPath(project, repoRoot);
        if (!File.Exists(path))
            return null;
        try
        {
            var report = JsonSerializer.Deserialize<FrontierReportDto>(File.ReadAllText(path), JsonOptions);
            return report is null ? null : ScareDoorProgressStore.EnrichReport(report, repoRoot);
        }
        catch (JsonException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    public static void Save(FrontierReportDto report, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var path = FrontierPath(report.Project, repoRoot);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(report, JsonOptions));
    }

    /// <summary>
    /// Composite score normalized to 0–100.
    /// </summary>
    public static int ComputeFrontierScore(
        int cfgDistance,
        double rarity,
        int unseenSuccessorCount,
        double sinkProximity)
    {
        var dist = Math.Clamp(cfgDistance, 1, 10);
        var rarityFactor = Math.Clamp(rarity, 0.05, 1.0);
        var unseenFactor = Math.Clamp(unseenSuccessorCount, 1, 8);
        var sinkFactor = Math.Clamp(sinkProximity, 0.05, 1.0);

        var product = dist * rarityFactor * unseenFactor * sinkFactor;
        return Math.Clamp((int)Math.Round(product * 12.5), 1, 100);
    }

    private static IEnumerable<FrontierBranchDto> ScoreCfgBranches(
        RandallAnalysisDocument doc,
        IReadOnlyList<GhidraCoverageOverlay.CoverageBlock> coverage,
        IReadOnlyList<StalkLayerDto> layers,
        string project,
        string repoRoot)
    {
        if (!GhidraCoverageOverlay.TryParseAddress(doc.ImageBase, out var imageBase))
            imageBase = 0;

        var layerHits = BuildLayerBlockHits(layers, project, repoRoot, imageBase);

        foreach (var fn in doc.Functions)
        {
            var cfgBlocks = fn.Cfg?.Blocks ?? [];
            if (cfgBlocks.Count == 0)
                continue;

            var blockStates = cfgBlocks
                .Select(bb => (Block: bb, Covered: GhidraCoverageOverlay.IsBlockCovered(bb, coverage, imageBase)))
                .ToList();

            var addrToIndex = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            for (var i = 0; i < blockStates.Count; i++)
                addrToIndex[blockStates[i].Block.Address] = i;

            var dist = ComputeDistancesFromCovered(blockStates, addrToIndex);
            var sinkProximity = Math.Clamp(MaxSinkRisk(fn), 1, 100) / 100.0;

            for (var i = 0; i < blockStates.Count; i++)
            {
                var (block, covered) = blockStates[i];
                if (covered || dist[i] == int.MaxValue)
                    continue;

                var unseenSucc = block.Successors.Count(s =>
                    addrToIndex.TryGetValue(s, out var j) && !blockStates[j].Covered);

                var coveredPreds = block.Predecessors
                    .Where(p => addrToIndex.TryGetValue(p, out var j) && blockStates[j].Covered)
                    .ToList();

                if (coveredPreds.Count == 0 && dist[i] > 1)
                    continue;

                var cfgDistance = dist[i] == int.MaxValue ? blockStates.Count : dist[i];
                var predAddr = coveredPreds.FirstOrDefault() ?? block.Predecessors.FirstOrDefault() ?? fn.Address;
                var rarity = ComputeRarity(predAddr, layers.Count, layerHits);
                var score = ComputeFrontierScore(cfgDistance, rarity, Math.Max(1, unseenSucc), sinkProximity);
                var edgeKey = $"{fn.Name}:{predAddr}->{block.Address}";
                var approach = coveredPreds.Sum(p =>
                    layerHits.GetValueOrDefault(NormalizeAddr(p)));
                if (approach == 0)
                    approach = layerHits.GetValueOrDefault(NormalizeAddr(predAddr));
                var crossed = layerHits.GetValueOrDefault(NormalizeAddr(block.Address));

                yield return new FrontierBranchDto(
                    edgeKey,
                    "cfg-branch",
                    score,
                    cfgDistance,
                    Math.Round(rarity, 4),
                    Math.Max(1, unseenSucc),
                    Math.Round(sinkProximity, 4),
                    fn.Name,
                    predAddr,
                    block.Address,
                    null,
                    $"Uncovered BB {cfgDistance} hop(s) from coverage; {unseenSucc} unseen successor(s); sink×{sinkProximity:P0}.",
                    approach,
                    crossed);
            }
        }
    }

    private static IEnumerable<FrontierBranchDto> ScoreSessionForks(
        string project,
        FuzzSessionStatusDto? liveStatus)
    {
        StalkDashboardDto? dash;
        try
        {
            dash = StalkDashboard.ForProject(project, liveStatus, null);
        }
        catch
        {
            yield break;
        }

        if (dash is null)
            yield break;

        var unexplored = dash.Blocks
            .Where(b => string.Equals(b.Kind, "unexplored", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (unexplored.Count == 0)
            yield break;

        foreach (var block in unexplored)
        {
            var cmd = block.Command ?? block.Label ?? block.Id;
            var unseen = Math.Max(1, unexplored.Count - 1);
            var sinkProximity = string.IsNullOrWhiteSpace(block.Mutator) ? 0.55 : 0.75;
            var rarity = 0.85;
            var score = ComputeFrontierScore(1, rarity, unseen, sinkProximity);
            var addr = string.IsNullOrWhiteSpace(block.Address) ? block.Id : block.Address;
            var edgeKey = string.IsNullOrWhiteSpace(block.Address)
                ? $"session:{block.Id}"
                : $"{block.Module ?? "session"}:{block.Address}:fork";

            yield return new FrontierBranchDto(
                edgeKey,
                "session-fork",
                score,
                1,
                rarity,
                unseen,
                sinkProximity,
                cmd,
                "__entry",
                addr,
                block.Module ?? "session",
                string.IsNullOrWhiteSpace(block.Detail)
                    ? $"Session fork '{cmd}' is known but not on the exercised path."
                    : block.Detail);
        }
    }

    private static IEnumerable<FrontierBranchDto> ScoreEdgeGaps(string project, string repoRoot, int limit)
    {
        var missed = MissedBlockAnalyzer.Analyze(project, repoRoot, limit: limit * 2);
        foreach (var gap in missed.Blocks.Where(b => b.Category is "frontier-gap" or "baseline-only"))
        {
            var rarity = gap.Category == "baseline-only" ? 0.7 : 0.6;
            var score = ComputeFrontierScore(3, rarity, 2, 0.5);
            yield return new FrontierBranchDto(
                gap.EdgeKey,
                "edge-gap",
                Math.Max(score, gap.PriorityScore / 2),
                3,
                rarity,
                2,
                0.5,
                null,
                gap.NearbyHitAddress,
                gap.Address,
                gap.Module,
                gap.WhyMissed);
        }
    }

    private static int[] ComputeDistancesFromCovered(
        IReadOnlyList<(RandallAnalysisBasicBlockDto Block, bool Covered)> blockStates,
        IReadOnlyDictionary<string, int> addrToIndex)
    {
        var dist = Enumerable.Repeat(int.MaxValue, blockStates.Count).ToArray();
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

        return dist;
    }

    private static double ComputeRarity(
        string blockAddress,
        int layerCount,
        IReadOnlyDictionary<string, int> layerHits)
    {
        if (layerCount == 0)
            return 1.0;

        layerHits.TryGetValue(NormalizeAddr(blockAddress), out var hits);
        var fraction = hits / (double)Math.Max(1, layerCount);
        return Math.Clamp(1.0 - fraction, 0.1, 1.0);
    }

    private static Dictionary<string, int> BuildLayerBlockHits(
        IReadOnlyList<StalkLayerDto> layers,
        string project,
        string repoRoot,
        ulong imageBase)
    {
        var hits = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var layer in layers)
        {
            var seenInLayer = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var edge in StalkCampaignStore.LoadEdges(project, layer.Id, repoRoot))
            {
                if (!GhidraCoverageOverlay.TryParseCoverageEdge(edge, out var block))
                    continue;
                var addr = $"0x{(imageBase + block.Start):x}";
                if (!seenInLayer.Add(addr))
                    continue;
                hits.TryGetValue(NormalizeAddr(addr), out var n);
                hits[NormalizeAddr(addr)] = n + 1;
            }
        }

        return hits;
    }

    private static string NormalizeAddr(string addr) =>
        addr.Trim().ToLowerInvariant();

    private static int MaxSinkRisk(RandallAnalysisFunctionDto fn)
    {
        if (fn.DangerousCalls.Count == 0)
            return fn.InputReachable ? 35 : 25;
        return fn.DangerousCalls.Max(GhidraAnalysisBridge.SinkRisk);
    }

    private static string ResolveMode(RandallAnalysisDocument? analysis, IReadOnlyList<FrontierBranchDto> frontiers)
    {
        if (frontiers.Count == 0)
            return "empty";
        var hasCfg = frontiers.Any(f => f.Kind == "cfg-branch");
        var hasSession = frontiers.Any(f => f.Kind == "session-fork");
        if (hasCfg && hasSession)
            return "mixed";
        if (hasCfg || analysis is not null)
            return "cfg";
        return hasSession ? "session" : "edge-gap";
    }

    private static string BuildSummary(
        IReadOnlyList<FrontierBranchDto> frontiers,
        int coverageBlocks,
        RandallAnalysisDocument? analysis)
    {
        if (frontiers.Count == 0)
        {
            if (analysis is null && coverageBlocks == 0)
                return "No coverage or static map — record stalk layers or run ghidra-analyze.";
            if (analysis is null)
                return $"{coverageBlocks} coverage blocks but no randall-analysis.json — session/edge gaps only.";
            return "All known CFG blocks covered (or none reachable from coverage).";
        }

        var top = frontiers[0];
        return $"{frontiers.Count} gray door(s); top [{top.Score}] {top.Kind} → {top.ToAddress} " +
               $"(d={top.CfgDistance:0} r={top.Rarity:P0} succ={top.UnseenSuccessorCount}).";
    }
}
