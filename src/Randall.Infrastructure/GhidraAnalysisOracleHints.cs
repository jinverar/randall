using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Light Oracle companion: surface Ghidra static map priorities alongside runtime findings.
/// </summary>
public static class GhidraAnalysisOracleHints
{
    public sealed record HintPack(
        string Project,
        string AnalysisPath,
        IReadOnlyList<RandallAnalysisFunctionDto> TopFunctions,
        IReadOnlyList<RandallAnalysisFunctionDto> TopUncoveredTargets,
        IReadOnlyList<RandallAnalysisSinkDto> TopSinks,
        IReadOnlyList<RandallAnalysisChangedFunctionDto> TopChangedFunctions,
        IReadOnlyList<RandallAnalysisSourceSinkPathDto> TopSourceSinkPaths,
        RandallAnalysisCoverageSummaryDto? CoverageSummary,
        string Summary,
        string CoverageGapSummary,
        string UnopenedDoorsSummary,
        string? PatchHuntSummary = null);

    public static HintPack? TryBuild(string project, string? repoRoot = null)
    {
        var path = GhidraAnalysisBridge.AnalysisPath(project, repoRoot);
        var doc = GhidraAnalysisBridge.TryLoad(project, repoRoot);
        if (doc is null)
            return null;

        var topFn = doc.Functions
            .OrderByDescending(f => f.FuzzPriority)
            .Take(8)
            .ToList();
        var topUncovered = doc.Functions
            .Where(f => f.UncoveredBlockCount > 0 || f.CoverageFraction is < 1.0)
            .OrderByDescending(f => f.FuzzPriority)
            .ThenByDescending(f => f.UncoveredBlockCount)
            .Take(8)
            .ToList();
        var topSink = doc.Sinks
            .OrderByDescending(s => s.Risk)
            .Take(6)
            .ToList();
        var topChanged = (doc.ChangedFunctions ?? [])
            .OrderByDescending(c => c.ChangeScore)
            .Take(6)
            .ToList();
        var topPaths = (doc.SourceSinkPaths ?? SourceSinkPathScorer.ScorePaths(doc))
            .Take(6)
            .ToList();

        var summary = topFn.Count == 0
            ? "Static map loaded (no functions)."
            : $"Static map: {doc.Functions.Count} fn, {doc.Sinks.Count} sinks — top target {topFn[0].Name} ({topFn[0].FuzzPriority}/100).";
        if (topPaths.Count > 0)
            summary += $" Top source→sink: {topPaths[0].SourceSymbol}→{topPaths[0].SinkSymbol} (score {topPaths[0].PathScore}).";

        var gapSummary = BuildCoverageGapSummary(doc);
        var frontier = FrontierEngine.TryLoad(project, repoRoot);
        var unopened = BuildUnopenedDoorsSummary(doc, frontier);
        var patchHunt = BuildPatchHuntSummary(doc, topChanged);

        return new HintPack(
            project,
            path,
            topFn,
            topUncovered,
            topSink,
            topChanged,
            topPaths,
            doc.CoverageSummary,
            summary,
            gapSummary,
            unopened,
            patchHunt);
    }

    public static int StaticMapScoreBonus(string? functionName, RandallAnalysisDocument? doc)
    {
        if (doc is null || string.IsNullOrWhiteSpace(functionName))
            return 0;
        var fn = doc.Functions.FirstOrDefault(f =>
            f.Name.Equals(functionName, StringComparison.OrdinalIgnoreCase));
        if (fn is null)
            return 0;

        var baseBonus = Math.Clamp(fn.FuzzPriority / 10, 0, 10);
        var pathBonus = SourceSinkPathScorer.PathScoreBonus(functionName, doc);
        if (fn.CoverageFraction is null or >= 1.0)
        {
            var patchBonus = PatchHuntBonusForFunction(functionName, doc);
            return Math.Clamp(baseBonus + patchBonus + pathBonus, 0, 20);
        }

        var gapBoost = Math.Clamp((int)((1.0 - fn.CoverageFraction.Value) * 5), 0, 5);
        var patch = PatchHuntBonusForFunction(functionName, doc);
        return Math.Clamp(baseBonus + gapBoost + patch + pathBonus, 0, 20);
    }

    public static int PatchHuntBonusForFunction(string? functionName, RandallAnalysisDocument? doc)
    {
        if (doc?.ChangedFunctions is not { Count: > 0 } changed ||
            string.IsNullOrWhiteSpace(functionName))
            return 0;

        var hit = changed.FirstOrDefault(c =>
            c.Name.Equals(functionName, StringComparison.OrdinalIgnoreCase) ||
            (c.BaselineName?.Equals(functionName, StringComparison.OrdinalIgnoreCase) ?? false));
        if (hit is null)
            return 0;

        return Math.Clamp((int)Math.Round(hit.ChangeScore / 10.0), 1, 8);
    }

    public static RandallAnalysisFunctionDto? FindFunctionByAddress(
        RandallAnalysisDocument doc,
        string address)
    {
        if (!CrashStaticFunctionMapper.TryParseAddress(address, out var target))
            return null;

        if (!CrashStaticFunctionMapper.TryParseAddress(doc.ImageBase, out var imageBase))
            imageBase = 0;

        foreach (var fn in doc.Functions)
        {
            if (!CrashStaticFunctionMapper.TryParseAddress(fn.Address, out var fnVa))
                continue;
            var size = (ulong)Math.Max(fn.Size, 1);
            if (target >= fnVa && target < fnVa + size)
                return fn;
            var fnRva = fnVa >= imageBase ? fnVa - imageBase : fnVa;
            if (target >= imageBase && target - imageBase >= fnRva && target - imageBase < fnRva + size)
                return fn;
        }

        return doc.Functions.FirstOrDefault(f =>
            CrashStaticFunctionMapper.TryParseAddress(f.Address, out var fa) && fa == target);
    }

    private static string BuildCoverageGapSummary(RandallAnalysisDocument doc)
    {
        if (doc.CoverageSummary is null)
            return "Coverage overlay: no stalk layers / edges yet — run fuzz with drcov or add stalk layers.";

        var s = doc.CoverageSummary;
        var pct = (int)Math.Round(s.CoverageFraction * 100);
        var top = s.TopUncoveredTargets.Count == 0
            ? "none ranked"
            : string.Join(", ", s.TopUncoveredTargets.Take(4));
        return
            $"Coverage overlay: {s.CoveredBlocks}/{s.TotalBlocks} BBs ({pct}%), " +
            $"{s.FunctionsWithGaps} fn with gaps — focus: {top}.";
    }

    private static string BuildUnopenedDoorsSummary(
        RandallAnalysisDocument doc,
        FrontierReportDto? frontier)
    {
        var parts = new List<string>();

        if (doc.CoverageSummary is not null)
        {
            var s = doc.CoverageSummary;
            if (s.UncoveredBlocks > 0)
            {
                var names = s.TopUncoveredTargets.Count > 0
                    ? string.Join(", ", s.TopUncoveredTargets.Take(3))
                    : "high-priority gaps";
                parts.Add($"{s.UncoveredBlocks} unopened BB(s) in {names}");
            }
        }
        else
        {
            var uncovered = doc.Functions
                .Where(f => f.UncoveredBlockCount > 0)
                .OrderByDescending(f => f.FuzzPriority)
                .Take(3)
                .Select(f => f.Name)
                .ToList();
            if (uncovered.Count > 0)
                parts.Add($"static gaps in {string.Join(", ", uncovered)}");
        }

        if (frontier?.Frontiers is { Count: > 0 } doors)
        {
            var top = doors.Take(3)
                .Select(f => string.IsNullOrWhiteSpace(f.FunctionName)
                    ? f.ToAddress
                    : $"{f.FunctionName}→{f.ToAddress}")
                .ToList();
            parts.Add($"{doors.Count} gray door(s): {string.Join("; ", top)}");
        }

        return parts.Count == 0
            ? "Unopened doors: run stalk frontier after coverage layers for ranked gray branches."
            : "Unopened doors: " + string.Join(" · ", parts);
    }

    private static string? BuildPatchHuntSummary(
        RandallAnalysisDocument doc,
        IReadOnlyList<RandallAnalysisChangedFunctionDto> topChanged)
    {
        if (topChanged.Count == 0)
            return doc.DiffMeta is null
                ? null
                : "Patch-hunt: baseline merged — no function deltas above threshold.";

        var top = topChanged.Take(3)
            .Select(c => $"{c.Name} ({c.ChangeKind}, score {c.ChangeScore:0})")
            .ToList();
        var source = doc.DiffMeta?.Source ?? "json-merge";
        return $"Patch-hunt ({source}): prioritize {string.Join(", ", top)}.";
    }
}
