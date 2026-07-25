using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Optional soft corpus energy bias when Ghidra static map shows coverage gaps.
/// Per-crash function correlation: <see cref="CrashStaticFunctionMapper"/>.
/// </summary>
public static class GhidraStaticMapBias
{
    public static int NovelCoverageEnergyBoost(
        string project,
        int newEdges,
        bool enabled,
        string? repoRoot = null)
    {
        if (!enabled || newEdges <= 0 || string.IsNullOrWhiteSpace(project))
            return 0;

        var doc = GhidraAnalysisBridge.TryLoad(project, repoRoot);
        if (doc?.CoverageSummary is null)
            return 0;

        var gap = 1.0 - doc.CoverageSummary.CoverageFraction;
        if (gap <= 0.01)
            return 0;

        var topUncovered = doc.Functions
            .Where(f => f.UncoveredBlockCount > 0)
            .OrderByDescending(f => f.FuzzPriority)
            .FirstOrDefault();
        var priorityFactor = (topUncovered?.FuzzPriority ?? 50) / 100.0;

        var patchFactor = 1.0;
        if (doc.ChangedFunctions is { Count: > 0 } changed)
        {
            var top = changed.Max(c => c.ChangeScore);
            patchFactor += Math.Min(0.35, top / 200.0);
        }

        var boost = (int)Math.Round(Math.Min(10.0, newEdges * gap * priorityFactor * patchFactor * 2.0));
        return Math.Max(1, boost);
    }
}
