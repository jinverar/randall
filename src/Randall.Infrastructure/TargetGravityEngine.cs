using System.Globalization;
using System.Text.Json;
using Randall.Contracts;
using Randall.Infrastructure.Oracles;

namespace Randall.Infrastructure;

/// <summary>
/// Reachability pressure / TargetGravity for stalking: risk × unexploredness / distance from covered
/// basic blocks toward strcpy-like sinks, allocators, Ghidra-marked dangerous calls, and oracle near-misses.
/// Integrates DynamoRIO/missed-block/Ghidra overlay when present; stalk-only when static map is absent.
/// </summary>
public static class TargetGravityEngine
{
    public const string FileName = "target_gravity.json";
    private const double StaleWellDecay = 0.82;
    private const int MinStaleWellScore = 12;
    private const int DefaultTopSnapshotCount = 5;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
    };

    public static string GravityPath(string project, string? repoRoot = null) =>
        Path.Combine(StalkCampaignStore.ProjectDir(project, repoRoot), FileName);

    /// <summary>Top gravity score + label for optional HuntPolicy read (null when no report).</summary>
    public static (int Score, string Label)? TryGetTopPressure(string? project, string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(project))
            return null;

        var report = TryLoad(project, repoRoot);
        if (report is null || report.Wells.Count == 0)
            return null;

        var top = report.Wells[0];
        var label = top.SinkSymbol ?? top.FunctionName ?? top.Address ?? top.Kind;
        return (top.GravityScore, label);
    }

    public static TargetGravityReportDto Score(
        string project,
        string? repoRoot = null,
        int limit = 40,
        FuzzSessionStatusDto? liveStatus = null,
        bool persist = true,
        string? binaryPath = null)
    {
        if (string.IsNullOrWhiteSpace(project))
            throw new ArgumentException("project required");

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        limit = Math.Clamp(limit, 1, 200);

        var coverage = GhidraCoverageOverlay.LoadStalkCoverage(project, repoRoot);
        var analysis = GhidraAnalysisBridge.TryLoad(project, repoRoot);
        if (analysis is not null)
            analysis = GhidraCoverageOverlay.Apply(analysis, project, repoRoot);

        var oracleFindings = LoadRecentOracleFindings(project, repoRoot, 12);
        var resolvedBinary = StalkMapBuilder.ResolveBinary(project, null, binaryPath, repoRoot);
        var surface = resolvedBinary is not null ? BinarySurfaceMap.TryLoad(resolvedBinary) : null;

        var wells = new List<TargetGravityWellDto>();
        if (analysis is not null)
            wells.AddRange(ScoreCfgWells(analysis, coverage, project, repoRoot));
        wells.AddRange(ScoreSurfaceWells(project, repoRoot, surface, liveStatus));
        wells.AddRange(ScoreOracleWells(oracleFindings, analysis, coverage));

        wells = MergeWithStaleDecay(wells, TryLoad(project, repoRoot));

        wells = wells
            .GroupBy(w => w.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(x => x.GravityScore).First())
            .OrderByDescending(w => w.GravityScore)
            .ThenByDescending(w => w.Risk)
            .ThenBy(w => w.Distance)
            .ThenBy(w => w.Address ?? w.Key, StringComparer.OrdinalIgnoreCase)
            .Take(limit)
            .ToList();

        var mode = ResolveMode(wells, analysis);
        var aggregate = wells.Count == 0
            ? 0
            : Math.Clamp((int)Math.Round(wells.Take(5).Average(w => w.GravityScore)), 0, 100);
        var summary = BuildSummary(wells, coverage.Count, analysis);
        var topSnapshots = BuildTopSnapshots(wells, DefaultTopSnapshotCount);
        var report = new TargetGravityReportDto(
            project,
            DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture),
            mode,
            summary,
            coverage.Count,
            wells.Count,
            aggregate,
            wells,
            "Bias seeds toward high-gravity sinks; pair with randall stalk map / frontier gray doors.",
            topSnapshots);

        if (persist)
            Save(report, repoRoot);

        return report;
    }

    /// <summary>Refresh and persist gravity after stalk map / layer updates (decays stale wells).</summary>
    public static TargetGravityReportDto RefreshForStalkMap(
        string project,
        string? repoRoot = null,
        int limit = 40,
        FuzzSessionStatusDto? liveStatus = null,
        string? binaryPath = null) =>
        Score(project, repoRoot, limit, liveStatus, persist: true, binaryPath);

    private static List<TargetGravityWellDto> MergeWithStaleDecay(
        IReadOnlyList<TargetGravityWellDto> fresh,
        TargetGravityReportDto? prior)
    {
        if (prior?.Wells is not { Count: > 0 })
            return fresh.ToList();

        var merged = fresh.ToList();
        var freshKeys = new HashSet<string>(fresh.Select(w => w.Key), StringComparer.OrdinalIgnoreCase);
        foreach (var old in prior.Wells)
        {
            if (freshKeys.Contains(old.Key))
                continue;

            var decayed = Math.Max(1, (int)Math.Round(old.GravityScore * StaleWellDecay));
            if (decayed < MinStaleWellScore)
                continue;

            merged.Add(old with
            {
                GravityScore = decayed,
                Detail = $"Stale pressure (decayed): {old.Detail}",
            });
        }

        return merged;
    }

    private static IReadOnlyList<TargetGravityTopSnapshotDto> BuildTopSnapshots(
        IReadOnlyList<TargetGravityWellDto> wells,
        int count)
    {
        count = Math.Clamp(count, 1, 20);
        return wells
            .Take(count)
            .Select(w => new TargetGravityTopSnapshotDto(
                w.Key,
                w.GravityScore,
                w.SinkSymbol ?? w.FunctionName ?? w.Address ?? w.Kind,
                w.Detail))
            .ToList();
    }

    public static TargetGravityReportDto? TryLoad(string project, string? repoRoot = null)
    {
        var path = GravityPath(project, repoRoot);
        if (!File.Exists(path))
            return null;
        try
        {
            var report = JsonSerializer.Deserialize<TargetGravityReportDto>(File.ReadAllText(path), JsonOptions);
            if (report is null)
                return null;
            if (report.TopSnapshots is null or { Count: 0 } && report.Wells.Count > 0)
                return report with { TopSnapshots = BuildTopSnapshots(report.Wells, DefaultTopSnapshotCount) };
            return report;
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

    public static void Save(TargetGravityReportDto report, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var path = GravityPath(report.Project, repoRoot);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(report, JsonOptions));
    }

    /// <summary>
    /// TargetGravity ≈ risk × unexploredness / distance, normalized to 0–100.
    /// </summary>
    public static int ComputeGravityScore(double risk, double unexploredness, int distance)
    {
        var r = Math.Clamp(risk, 1, 100) / 100.0;
        var u = Math.Clamp(unexploredness, 0.05, 1.0);
        var d = Math.Max(1, distance);
        var raw = r * u / d * 100.0;
        return Math.Clamp((int)Math.Round(raw), 1, 100);
    }

    /// <summary>Lookup gravity score for a missed-block address (hex substring match).</summary>
    public static int LookupGravityForAddress(TargetGravityReportDto? report, string address)
    {
        if (report is null || report.Wells.Count == 0 || string.IsNullOrWhiteSpace(address))
            return 0;

        var needle = NormalizeAddr(address);
        var well = report.Wells.FirstOrDefault(w =>
            w.Address is not null && NormalizeAddr(w.Address).Contains(needle, StringComparison.OrdinalIgnoreCase));
        return well?.GravityScore ?? 0;
    }

    private static IEnumerable<TargetGravityWellDto> ScoreCfgWells(
        RandallAnalysisDocument doc,
        IReadOnlyList<GhidraCoverageOverlay.CoverageBlock> coverage,
        string project,
        string repoRoot)
    {
        if (!GhidraCoverageOverlay.TryParseAddress(doc.ImageBase, out var imageBase))
            imageBase = 0;

        var layers = StalkCampaignStore.ListLayers(project, repoRoot);
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
            var fnRisk = MaxSinkRisk(fn);
            var fnUnexplored = fn.CoverageFraction is { } frac
                ? Math.Clamp(1.0 - frac, 0.05, 1.0)
                : blockStates.Count(b => !b.Covered) / (double)Math.Max(1, blockStates.Count);

            for (var i = 0; i < blockStates.Count; i++)
            {
                var (block, covered) = blockStates[i];
                if (covered || dist[i] == int.MaxValue)
                    continue;

                var distance = Math.Clamp(dist[i], 1, 12);
                var blockUnexplored = Math.Max(fnUnexplored, 0.85);
                var rarityBoost = 1.0 - layerHits.GetValueOrDefault(NormalizeAddr(block.Address)) /
                                  (double)Math.Max(1, layers.Count);
                var unexploredness = Math.Clamp(blockUnexplored * Math.Clamp(rarityBoost, 0.2, 1.0), 0.05, 1.0);
                var score = ComputeGravityScore(fnRisk, unexploredness, distance);
                var sink = fn.DangerousCalls.FirstOrDefault() ?? fn.Name;
                var kind = ClassifySinkKind(sink);

                yield return new TargetGravityWellDto(
                    $"cfg:{fn.Name}:{block.Address}",
                    kind,
                    score,
                    fnRisk,
                    Math.Round(unexploredness, 4),
                    distance,
                    fn.Name,
                    block.Address,
                    sink,
                    $"Uncovered BB {distance} hop(s) from coverage toward {sink} (risk {fnRisk}).");
            }
        }

        foreach (var sink in doc.Sinks.Where(s => s.Risk >= 40))
        {
            foreach (var caller in sink.Callers.Take(4))
            {
                var fn = doc.Functions.FirstOrDefault(f =>
                    f.Name.Equals(caller, StringComparison.OrdinalIgnoreCase));
                if (fn is null)
                    continue;

                var distance = fn.UncoveredDistance > 0 ? fn.UncoveredDistance : 3;
                var unexplored = fn.CoverageFraction is { } cf
                    ? Math.Clamp(1.0 - cf, 0.1, 1.0)
                    : 0.75;
                var score = ComputeGravityScore(sink.Risk, unexplored, Math.Max(1, distance));
                yield return new TargetGravityWellDto(
                    $"sink:{sink.Name}:{caller}",
                    ClassifySinkKind(sink.Name),
                    score,
                    sink.Risk,
                    Math.Round(unexplored, 4),
                    Math.Max(1, distance),
                    caller,
                    fn.Address,
                    sink.Name,
                    $"Ghidra sink {sink.Name} via {caller} — reachability pressure {score}/100.");
            }
        }
    }

    private static IEnumerable<TargetGravityWellDto> ScoreSurfaceWells(
        string project,
        string? repoRoot,
        BinarySurfaceMap? surface,
        FuzzSessionStatusDto? liveStatus)
    {
        var missed = MissedBlockAnalyzer.Analyze(project, repoRoot, limit: 80, liveStatus);
        foreach (var block in missed.Blocks.Take(40))
        {
            if (!TryParseAddr(block.Address, out var rva))
                continue;

            var risk = 35.0;
            var kind = "missed-surface";
            string? sink = null;

            if (surface is not null)
            {
                var nearImp = surface.NearbyImports(rva);
                var nearStr = surface.NearbyStrings(rva);
                foreach (var imp in nearImp)
                {
                    if (!BinarySurfaceMap.IsInterestingImport(imp))
                        continue;
                    var impRisk = GhidraAnalysisBridge.SinkRisk(imp);
                    if (impRisk > risk)
                    {
                        risk = impRisk;
                        sink = imp;
                        kind = ClassifySinkKind(imp);
                    }
                }

                if (nearStr.Any(BinarySurfaceMap.LooksDangerousString))
                    risk = Math.Max(risk, 55);
            }

            var distance = block.Category switch
            {
                "baseline-only" => 2,
                "frontier-gap" => 2,
                "never-hit" => 4,
                "session-unexplored" => 1,
                _ => 3,
            };
            var unexploredness = block.Category is "never-hit" or "baseline-only" ? 0.95 : 0.7;
            var score = ComputeGravityScore(risk, unexploredness, distance);

            yield return new TargetGravityWellDto(
                $"missed:{block.EdgeKey}",
                kind,
                score,
                risk,
                unexploredness,
                distance,
                block.Module,
                block.Address,
                sink,
                block.WhyMissed);
        }
    }

    private static IEnumerable<TargetGravityWellDto> ScoreOracleWells(
        IReadOnlyList<OracleFindingDto> findings,
        RandallAnalysisDocument? analysis,
        IReadOnlyList<GhidraCoverageOverlay.CoverageBlock> coverage)
    {
        foreach (var f in findings.Where(IsNearMiss).Take(6))
        {
            var risk = ScoreOracleRisk(f);
            var distance = EstimateOracleDistance(f, analysis, coverage);
            var unexploredness = 0.82;
            var score = ComputeGravityScore(risk, unexploredness, distance);
            yield return new TargetGravityWellDto(
                $"oracle:{f.Id}",
                "oracle-near-miss",
                score,
                risk,
                unexploredness,
                distance,
                f.Command,
                null,
                f.RuleId,
                $"{f.RuleClass} near-miss @ iter {f.Iteration} — {f.ExpectedRelation} vs {f.ActualRelation}");
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

    private static int MaxSinkRisk(RandallAnalysisFunctionDto fn)
    {
        if (fn.DangerousCalls.Count == 0)
            return fn.InputReachable ? 35 : 25;
        return fn.DangerousCalls.Max(GhidraAnalysisBridge.SinkRisk);
    }

    private static string ClassifySinkKind(string symbol)
    {
        var s = symbol.ToLowerInvariant();
        if (s.Contains("alloc", StringComparison.Ordinal) || s.Contains("malloc", StringComparison.Ordinal)
            || s.Contains("realloc", StringComparison.Ordinal) || s.Contains("calloc", StringComparison.Ordinal)
            || s.Contains("free", StringComparison.Ordinal))
            return "alloc";
        if (GhidraAnalysisBridge.IsDangerousSink(symbol))
            return "ghidra-dangerous";
        return "sink-call";
    }

    private static bool IsNearMiss(OracleFindingDto f) =>
        f.Severity.Trim().ToLowerInvariant() is "nearmiss" or "near_miss" or "near-miss";

    private static double ScoreOracleRisk(OracleFindingDto f) =>
        f.OracleScoreTotal is { } total and > 0
            ? Math.Clamp(total, 30, 90)
            : f.Severity.Trim().ToLowerInvariant() switch
            {
                "violation" => 80,
                "runtime" => 65,
                _ => 48,
            };

    private static int EstimateOracleDistance(
        OracleFindingDto f,
        RandallAnalysisDocument? analysis,
        IReadOnlyList<GhidraCoverageOverlay.CoverageBlock> coverage)
    {
        if (analysis is null || coverage.Count == 0)
            return 3;

        var fn = analysis.Functions
            .Where(x => x.UncoveredBlockCount > 0)
            .OrderByDescending(x => x.FuzzPriority)
            .FirstOrDefault(x => !string.IsNullOrWhiteSpace(f.Command)
                                 && x.Name.Contains(f.Command!, StringComparison.OrdinalIgnoreCase));
        if (fn?.UncoveredDistance is > 0)
            return Math.Clamp(fn.UncoveredDistance, 1, 8);

        return coverage.Count >= 20 ? 4 : 2;
    }

    private static IReadOnlyList<OracleFindingDto> LoadRecentOracleFindings(string project, string repoRoot, int limit)
    {
        var crashesRoot = Path.Combine(repoRoot, "data", "crashes", project, "_oracles");
        if (!Directory.Exists(crashesRoot))
            return [];

        var store = new OracleFindingStore(crashesRoot);
        return store.List(project)
            .OrderByDescending(f => f.At)
            .Take(limit)
            .ToList();
    }

    private static string ResolveMode(IReadOnlyList<TargetGravityWellDto> wells, RandallAnalysisDocument? analysis)
    {
        if (wells.Count == 0)
            return "empty";

        var hasCfg = wells.Any(w => w.Key.StartsWith("cfg:", StringComparison.OrdinalIgnoreCase)
                                    || w.Key.StartsWith("sink:", StringComparison.OrdinalIgnoreCase));
        var hasSurface = wells.Any(w => w.Kind == "missed-surface");
        var hasOracle = wells.Any(w => w.Kind == "oracle-near-miss");

        if (hasCfg && (hasSurface || hasOracle))
            return "mixed";
        if (hasCfg || analysis is not null)
            return "cfg";
        if (hasOracle && hasSurface)
            return "mixed";
        if (hasOracle)
            return "oracle";
        return hasSurface ? "surface" : "empty";
    }

    private static string BuildSummary(
        IReadOnlyList<TargetGravityWellDto> wells,
        int coverageBlocks,
        RandallAnalysisDocument? analysis)
    {
        if (wells.Count == 0)
        {
            if (analysis is null && coverageBlocks == 0)
                return "No coverage or static map — record stalk layers or run ghidra-analyze.";
            if (analysis is null)
                return $"{coverageBlocks} coverage blocks — surface/oracle gravity only (no Ghidra CFG).";
            return "No reachability pressure wells — sinks may be fully covered.";
        }

        var top = wells[0];
        var sym = top.SinkSymbol ?? top.FunctionName ?? top.Address ?? top.Kind;
        return $"{wells.Count} gravity well(s); top [{top.GravityScore}] {top.Kind} → {sym} " +
               $"(risk={top.Risk:0} u={top.Unexploredness:P0} d={top.Distance}).";
    }

    private static string NormalizeAddr(string addr) => addr.Trim().ToLowerInvariant();

    private static bool TryParseAddr(string addr, out ulong rva)
    {
        rva = 0;
        var s = addr.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            s = s[2..];
        return ulong.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out rva);
    }
}
