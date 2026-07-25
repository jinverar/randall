using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Scream score helpers — mirrors Scare Floor hot/purple canister rules.</summary>
public static class ScreamScoreHelper
{
    /// <summary>Hot scream: high novelty plus oracle signal or first-in-cluster (purple mist in UI).</summary>
    public static bool IsHot(CrashSummaryDto crash)
    {
        var seen = crash.SeenCount > 0 ? crash.SeenCount : 1;
        return crash.Novelty >= 70 && (crash.OracleScoreTotal >= 40 || seen <= 1);
    }

    /// <summary>Evaluate scream-score goal against project crashes (0 goal = not met).</summary>
    public static bool GoalReached(int goal, IReadOnlyList<CrashSummaryDto> projectCrashes)
    {
        if (goal <= 0 || projectCrashes.Count == 0)
            return false;

        var maxScore = projectCrashes.Max(c => c.ScreamScore);
        var hotCount = projectCrashes.Count(IsHot);
        return maxScore >= goal || hotCount >= goal;
    }
}
