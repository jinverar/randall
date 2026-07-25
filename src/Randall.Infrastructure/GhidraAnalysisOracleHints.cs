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
        IReadOnlyList<RandallAnalysisSinkDto> TopSinks,
        string Summary);

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
        var topSink = doc.Sinks
            .OrderByDescending(s => s.Risk)
            .Take(6)
            .ToList();

        var summary = topFn.Count == 0
            ? "Static map loaded (no functions)."
            : $"Static map: {doc.Functions.Count} fn, {doc.Sinks.Count} sinks — top target {topFn[0].Name} ({topFn[0].FuzzPriority}/100).";

        return new HintPack(project, path, topFn, topSink, summary);
    }

    public static int StaticMapScoreBonus(string? functionName, RandallAnalysisDocument? doc)
    {
        if (doc is null || string.IsNullOrWhiteSpace(functionName))
            return 0;
        var fn = doc.Functions.FirstOrDefault(f =>
            f.Name.Equals(functionName, StringComparison.OrdinalIgnoreCase));
        return fn is null ? 0 : Math.Clamp(fn.FuzzPriority / 10, 0, 10);
    }

    public static RandallAnalysisFunctionDto? FindFunctionByAddress(
        RandallAnalysisDocument doc,
        string address)
    {
        if (!TryParseAddr(address, out var target))
            return null;
        return doc.Functions.FirstOrDefault(f =>
            TryParseAddr(f.Address, out var fa) && fa == target);
    }

    private static bool TryParseAddr(string addr, out ulong value)
    {
        value = 0;
        var s = addr.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            s = s[2..];
        return ulong.TryParse(s, System.Globalization.NumberStyles.HexNumber,
            System.Globalization.CultureInfo.InvariantCulture, out value);
    }
}
