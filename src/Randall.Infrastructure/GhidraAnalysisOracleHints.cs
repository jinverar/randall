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
        RandallAnalysisCoverageSummaryDto? CoverageSummary,
        string Summary,
        string CoverageGapSummary);

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

        var summary = topFn.Count == 0
            ? "Static map loaded (no functions)."
            : $"Static map: {doc.Functions.Count} fn, {doc.Sinks.Count} sinks — top target {topFn[0].Name} ({topFn[0].FuzzPriority}/100).";

        var gapSummary = BuildCoverageGapSummary(doc);

        return new HintPack(
            project,
            path,
            topFn,
            topUncovered,
            topSink,
            doc.CoverageSummary,
            summary,
            gapSummary);
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
        if (fn.CoverageFraction is null or >= 1.0)
            return baseBonus;

        var gapBoost = Math.Clamp((int)((1.0 - fn.CoverageFraction.Value) * 5), 0, 5);
        return Math.Clamp(baseBonus + gapBoost, 0, 12);
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
}
