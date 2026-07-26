using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Evaluates intelligence stop goals against project crashes (and optional evolution sidecars).
/// Keeps stop logic out of HuntPolicy / Hypothesis / ScreamEvolution cores.
/// </summary>
public static class IntelligenceStopGoalEvaluator
{
    public static IntelligenceStopGoalsConfig Resolve(FuzzConfig fuzz)
    {
        var goals = fuzz.StopGoals ?? new IntelligenceStopGoalsConfig();
        if (fuzz.ScreamScoreGoal > 0 && goals.LegacyScreamScoreGoal <= 0)
            goals.LegacyScreamScoreGoal = fuzz.ScreamScoreGoal;
        return goals;
    }

    public static IntelligenceStopGoalsConfig Merge(
        IntelligenceStopGoalsConfig? project,
        IntelligenceStopGoalsConfig? campaign,
        IntelligenceStopGoalsConfig? run)
    {
        var merged = new IntelligenceStopGoalsConfig();
        foreach (var src in new[] { project, campaign, run })
        {
            if (src is null)
                continue;
            if (src.LegacyScreamScoreGoal > 0)
                merged.LegacyScreamScoreGoal = src.LegacyScreamScoreGoal;
            if (src.UniqueScreamsWithScore is { Count: > 0, MinScore: > 0 })
                merged.UniqueScreamsWithScore = src.UniqueScreamsWithScore;
            if (src.UniqueScreamsWithMomentum is { Count: > 0, MinMomentum: > 0 })
                merged.UniqueScreamsWithMomentum = src.UniqueScreamsWithMomentum;
            if (src.QueueTopClustersOnGoal)
                merged.QueueTopClustersOnGoal = true;
        }

        return merged;
    }

    public static IntelligenceStopGoalProgressDto Evaluate(
        IntelligenceStopGoalsConfig goals,
        IReadOnlyList<CrashSummaryDto> crashes,
        IReadOnlyDictionary<Guid, ScreamEvolutionDto>? evolutions = null)
    {
        if (!goals.IsEnabled || crashes.Count == 0)
            return new IntelligenceStopGoalProgressDto(false, null, EmptyCounters());

        var counters = new Dictionary<string, int>(StringComparer.Ordinal);
        var reasons = new List<string>();

        if (goals.LegacyScreamScoreGoal > 0)
        {
            var maxScore = crashes.Max(c => c.ScreamScore);
            var hotCount = crashes.Count(ScreamScoreHelper.IsHot);
            counters["maxScreamScore"] = maxScore;
            counters["hotScreamCount"] = hotCount;
            counters["legacyGoal"] = goals.LegacyScreamScoreGoal;
            if (ScreamScoreHelper.GoalReached(goals.LegacyScreamScoreGoal, crashes))
                reasons.Add($"legacy scream goal {goals.LegacyScreamScoreGoal} (max={maxScore}, hot={hotCount})");
        }

        if (goals.UniqueScreamsWithScore is { Count: > 0, MinScore: > 0 } scoreGoal)
        {
            var qualified = CountUniqueClustersAboveScore(crashes, scoreGoal.MinScore);
            counters["uniqueScoreClusters"] = qualified;
            counters["uniqueScoreClustersRequired"] = scoreGoal.Count;
            counters["uniqueScoreMinScore"] = scoreGoal.MinScore;
            if (qualified >= scoreGoal.Count)
                reasons.Add($"{qualified} unique clusters with score ≥ {scoreGoal.MinScore}");
        }

        if (goals.UniqueScreamsWithMomentum is { Count: > 0, MinMomentum: > 0 } momentumGoal)
        {
            var qualified = CountUniqueFamiliesAboveMomentum(crashes, evolutions, momentumGoal.MinMomentum);
            counters["uniqueMomentumFamilies"] = qualified;
            counters["uniqueMomentumFamiliesRequired"] = momentumGoal.Count;
            counters["uniqueMomentumMin"] = momentumGoal.MinMomentum;
            if (qualified >= momentumGoal.Count)
                reasons.Add($"{qualified} unique families with momentum ≥ {momentumGoal.MinMomentum}");
        }

        if (reasons.Count == 0)
            return new IntelligenceStopGoalProgressDto(false, null, counters);

        return new IntelligenceStopGoalProgressDto(
            true,
            $"Stop goal met: {string.Join("; ", reasons)}",
            counters);
    }

    public static IReadOnlyDictionary<Guid, ScreamEvolutionDto> LoadEvolutions(
        string repoRoot,
        string projectName,
        IReadOnlyList<CrashSummaryDto> crashes)
    {
        var crashesDir = Path.Combine(repoRoot, "data", "crashes", projectName);
        if (!Directory.Exists(crashesDir))
            return new Dictionary<Guid, ScreamEvolutionDto>();

        var map = new Dictionary<Guid, ScreamEvolutionDto>();
        foreach (var crash in crashes)
        {
            var evo = ScreamEvolutionBuilder.TryRead(ScreamEvolutionBuilder.PathFor(crashesDir, crash.Id));
            if (evo is not null)
                map[crash.Id] = evo;
        }

        return map;
    }

    /// <summary>
    /// Lightweight post-goal hook: enqueue replay/minimize experiments for top scream clusters.
    /// </summary>
    public static int TryQueueTopClusters(
        string projectName,
        IReadOnlyList<CrashSummaryDto> crashes,
        string? repoRoot,
        int iteration,
        int topN = 3)
    {
        var repo = repoRoot ?? CrashCatalog.FindRepoRoot();
        if (repo is null || crashes.Count == 0)
            return 0;

        var crashesDir = Path.Combine(repo, "data", "crashes", projectName);
        if (!Directory.Exists(crashesDir))
            return 0;

        var top = crashes
            .GroupBy(c => c.ClusterKey ?? c.Id.ToString("N"), StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(c => c.ScreamScore).First())
            .OrderByDescending(c => c.ScreamScore)
            .Take(topN)
            .ToList();

        var queued = 0;
        foreach (var crash in top)
        {
            var sidecar = crash.SidecarPath is not null
                ? CrashSidecarWriter.TryRead(crash.SidecarPath)
                : null;
            var triage = CrashTriage.Classify(null, sidecar, crash);
            var evolution = ScreamEvolutionBuilder.TryRead(ScreamEvolutionBuilder.PathFor(crashesDir, crash.Id));
            var chain = CorruptionChainBuilder.TryRead(CorruptionChainBuilder.PathFor(crashesDir, crash.Id));
            var set = HypothesisEngine.Build(crash.Id, projectName, sidecar, triage, null, chain, evolution);
            var topHyp = HypothesisEngine.TopPending(set);
            if (topHyp is null)
                continue;
            HypothesisEngine.EnqueueFromHypothesis(projectName, topHyp, iteration, repo);
            queued++;
        }

        return queued;
    }

    public static IntelligenceStopGoalProgressDto EvaluateCampaign(
        IntelligenceStopGoalsConfig goals,
        string repoRoot,
        IEnumerable<string> projectNames)
    {
        var allCrashes = new List<CrashSummaryDto>();
        var allEvolutions = new Dictionary<Guid, ScreamEvolutionDto>();
        foreach (var name in projectNames.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var crashes = CrashCatalog.ListAll(repoRoot, name);
            allCrashes.AddRange(crashes);
            foreach (var (id, evo) in LoadEvolutions(repoRoot, name, crashes))
                allEvolutions[id] = evo;
        }

        return Evaluate(goals, allCrashes, allEvolutions);
    }

    private static int CountUniqueClustersAboveScore(IReadOnlyList<CrashSummaryDto> crashes, int minScore) =>
        crashes
            .GroupBy(c => c.ClusterKey ?? c.Id.ToString("N"), StringComparer.OrdinalIgnoreCase)
            .Count(g => g.Max(c => c.ScreamScore) >= minScore);

    private static int CountUniqueFamiliesAboveMomentum(
        IReadOnlyList<CrashSummaryDto> crashes,
        IReadOnlyDictionary<Guid, ScreamEvolutionDto>? evolutions,
        int minMomentum)
    {
        if (evolutions is null || evolutions.Count == 0)
            return 0;

        var families = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var crash in crashes)
        {
            if (!evolutions.TryGetValue(crash.Id, out var evo))
                continue;
            var family = evo.FamilyId;
            if (string.IsNullOrWhiteSpace(family))
                continue;
            families[family] = Math.Max(families.GetValueOrDefault(family), evo.MomentumScore);
        }

        return families.Count(kv => kv.Value >= minMomentum);
    }

    private static IReadOnlyDictionary<string, int> EmptyCounters() =>
        new Dictionary<string, int>(StringComparer.Ordinal);
}
