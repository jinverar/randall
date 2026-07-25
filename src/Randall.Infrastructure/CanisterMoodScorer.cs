namespace Randall.Infrastructure;

/// <summary>Harvest mood thresholds — mirrors Scream canister UI (docs/assets/canisters).</summary>
public static class CanisterMoodScorer
{
    public static string Score(int unique, int critical, int ipCount)
    {
        if (ipCount > 0) return "eip";
        if (unique <= 0) return "laughter";
        if (unique >= 8 || critical >= 3) return "virulent";
        if (unique >= 3 || critical >= 1) return "toxic";
        return "watching";
    }

    public static IReadOnlyDictionary<string, int> CountMoods(
        IEnumerable<(int Unique, int Critical, int IpCount)> projects)
    {
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["laughter"] = 0,
            ["watching"] = 0,
            ["toxic"] = 0,
            ["virulent"] = 0,
            ["eip"] = 0,
        };

        foreach (var p in projects)
        {
            var mood = Score(p.Unique, p.Critical, p.IpCount);
            counts[mood]++;
        }

        return counts;
    }
}
