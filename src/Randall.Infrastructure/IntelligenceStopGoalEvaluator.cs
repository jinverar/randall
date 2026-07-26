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

    /// <summary>Per-run goals: project + optional run override (campaign goals excluded).</summary>
    public static IntelligenceStopGoalsConfig MergeForRun(
        IntelligenceStopGoalsConfig? project,
        IntelligenceStopGoalsConfig? run) =>
        Merge(project, null, run);

    public static IntelligenceStopGoalProgressDto Evaluate(
        IntelligenceStopGoalsConfig goals,
        IReadOnlyList<CrashSummaryDto> crashes,
        IReadOnlyDictionary<Guid, ScreamEvolutionDto>? evolutions = null)
    {
        if (!goals.IsEnabled)
            return new IntelligenceStopGoalProgressDto(false, null, EmptyCounters(), []);

        var counters = new Dictionary<string, int>(StringComparer.Ordinal);
        var items = new List<IntelligenceStopGoalItemProgressDto>();
        var reasons = new List<string>();

        if (goals.LegacyScreamScoreGoal > 0)
        {
            var maxScore = crashes.Count == 0 ? 0 : crashes.Max(c => c.ScreamScore);
            var hotCount = crashes.Count(ScreamScoreHelper.IsHot);
            counters["maxScreamScore"] = maxScore;
            counters["hotScreamCount"] = hotCount;
            counters["legacyGoal"] = goals.LegacyScreamScoreGoal;
            items.Add(new IntelligenceStopGoalItemProgressDto(
                "legacy",
                "Legacy scream goal",
                Math.Max(maxScore, hotCount),
                goals.LegacyScreamScoreGoal));
            if (crashes.Count > 0 && ScreamScoreHelper.GoalReached(goals.LegacyScreamScoreGoal, crashes))
                reasons.Add($"legacy scream goal {goals.LegacyScreamScoreGoal} (max={maxScore}, hot={hotCount})");
        }

        if (goals.UniqueScreamsWithScore is { Count: > 0, MinScore: > 0 } scoreGoal)
        {
            var qualified = CountUniqueClustersAboveScore(crashes, scoreGoal.MinScore);
            counters["uniqueScoreClusters"] = qualified;
            counters["uniqueScoreClustersRequired"] = scoreGoal.Count;
            counters["uniqueScoreMinScore"] = scoreGoal.MinScore;
            items.Add(new IntelligenceStopGoalItemProgressDto(
                "uniqueScore",
                $"Unique clusters ≥ {scoreGoal.MinScore}",
                qualified,
                scoreGoal.Count));
            if (qualified >= scoreGoal.Count)
                reasons.Add($"{qualified} unique clusters with score ≥ {scoreGoal.MinScore}");
        }

        if (goals.UniqueScreamsWithMomentum is { Count: > 0, MinMomentum: > 0 } momentumGoal)
        {
            var qualified = CountUniqueFamiliesAboveMomentum(crashes, evolutions, momentumGoal.MinMomentum);
            counters["uniqueMomentumFamilies"] = qualified;
            counters["uniqueMomentumFamiliesRequired"] = momentumGoal.Count;
            counters["uniqueMomentumMin"] = momentumGoal.MinMomentum;
            items.Add(new IntelligenceStopGoalItemProgressDto(
                "uniqueMomentum",
                $"Unique families ≥ {momentumGoal.MinMomentum}",
                qualified,
                momentumGoal.Count));
            if (qualified >= momentumGoal.Count)
                reasons.Add($"{qualified} unique families with momentum ≥ {momentumGoal.MinMomentum}");
        }

        if (reasons.Count == 0)
            return new IntelligenceStopGoalProgressDto(false, null, counters, items);

        return new IntelligenceStopGoalProgressDto(
            true,
            $"Stop goal met: {string.Join("; ", reasons)}",
            counters,
            items);
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

    /// <summary>
    /// Campaign aggregate: unique clusters/families are scoped per project (project:clusterKey).
    /// </summary>
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
            foreach (var crash in crashes)
            {
                allCrashes.Add(CampaignScopedCrash(name, crash));
                var evo = ScreamEvolutionBuilder.TryRead(
                    ScreamEvolutionBuilder.PathFor(Path.Combine(repoRoot, "data", "crashes", name), crash.Id));
                if (evo is not null)
                    allEvolutions[crash.Id] = evo;
            }
        }

        return Evaluate(goals, allCrashes, allEvolutions);
    }

    private static CrashSummaryDto CampaignScopedCrash(string projectName, CrashSummaryDto crash)
    {
        var cluster = crash.ClusterKey ?? crash.Id.ToString("N");
        return crash with { ClusterKey = $"{projectName}:{cluster}" };
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
            var scoped = $"{crash.Project}:{family}";
            families[scoped] = Math.Max(families.GetValueOrDefault(scoped), evo.MomentumScore);
        }

        return families.Count(kv => kv.Value >= minMomentum);
    }

    private static IReadOnlyDictionary<string, int> EmptyCounters() =>
        new Dictionary<string, int>(StringComparer.Ordinal);
}
