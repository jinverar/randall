using System.Text.Json;
using Randall.Contracts;
using Randall.Core;
using Randall.Infrastructure.Magician;

namespace Randall.Infrastructure;

/// <summary>
/// Phase B Hunt Policy — consolidates intelligence signals into one explainable HuntValue and
/// an execution mode (lineage breed vs havoc vs Joker timing). No LLM; research-only steering.
/// </summary>
public static class HuntPolicyEngine
{
    public const string LastPolicyFileName = "hunt_policy_last.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public sealed record Context(
        RandallBrain.Signals Signals,
        IReadOnlyList<MutatorCreditRowDto> MutatorRows,
        IReadOnlyList<MutatorChainRowDto>? ChainRows,
        IReadOnlyList<IMutator> Mutators,
        double CoverageFraction,
        int Iteration,
        double MemoryConfidence = 1.0,
        double BaseJokerChance = 0.0,
        string? Project = null,
        string? RepoRoot = null);

    public static string LastPolicyPath(string project, string? repoRoot = null) =>
        Path.Combine(StalkCampaignStore.ProjectDir(project, repoRoot), LastPolicyFileName);

    public static HuntPolicyDecision Evaluate(Context ctx)
    {
        if (!ctx.Signals.HasData)
            return HuntPolicyDecision.Inactive();

        var candidates = RandallBrain.BuildCandidates(ctx.Signals, ctx.MutatorRows);
        if (candidates.Count == 0)
            return HuntPolicyDecision.Inactive();

        var scored = candidates
            .Select(c => ScoreCandidate(c, ctx))
            .OrderByDescending(x => x.Value)
            .ThenBy(x => x.Candidate.Label, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var top = scored[0];
        var terms = new List<OracleScoreTerm>(top.Terms);

        var saturated = ctx.Signals.ScreamClusters.Count(s => s.Saturated);
        var stagnantNull = ctx.Signals.ScreamClusters.Count(s => s.IsStagnantNullDeref);
        if (saturated > 0)
            terms.Add(new OracleScoreTerm("duplicate penalty", -Math.Min(12, saturated * 3),
                $"{saturated} saturated familie(s)"));
        if (stagnantNull > 0)
            terms.Add(new OracleScoreTerm("null-deref stagnation", -Math.Min(10, stagnantNull * 4),
                $"{stagnantNull} READ-only familie(s)"));

        var exhausted = ComputeExhaustionPenalty(ctx);
        if (exhausted < 0)
            terms.Add(new OracleScoreTerm("exhaustion", exhausted, "high coverage · low yield"));

        var warming = ctx.Signals.ScreamClusters.Where(s => s.MomentumScore >= 40 && !s.Saturated).ToList();
        if (warming.Count > 0 && top.Candidate.Kind != "scream")
            terms.Add(new OracleScoreTerm("scream evolution", Math.Min(14, warming.Count * 4),
                $"{warming.Count} warming familie(s)"));

        var huntValue = Math.Clamp(terms.Sum(t => t.Points), 0, 100);
        var mode = ResolveMode(top, ctx, huntValue, warming);
        var preferredMutator = ResolvePreferredMutator(top.Candidate, ctx, mode);
        var lineageChain = ResolveLineageChain(ctx, mode, preferredMutator);
        var jokerChance = ResolveJokerChance(ctx, mode, huntValue, exhausted, stagnantNull);
        var (needsExperiment, experimentHint, topHypothesis) = ResolveExperiment(ctx, top.Candidate);

        var summary = BuildSummary(mode, top.Candidate, huntValue, jokerChance, preferredMutator);
        if (topHypothesis is not null && needsExperiment)
        {
            summary +=
                $" · hyp={topHypothesis.Id} ({topHypothesis.ConfidencePercent}%)";
        }

        return new HuntPolicyDecision(
            huntValue,
            mode,
            summary,
            jokerChance,
            needsExperiment,
            experimentHint,
            terms,
            top.Candidate.Kind,
            top.Candidate.Label,
            top.Candidate.Score,
            preferredMutator,
            lineageChain,
            topHypothesis?.Id,
            topHypothesis?.ConfidencePercent ?? 0,
            topHypothesis?.Statement);
    }

    public static bool ShouldInvokeJoker(HuntPolicyDecision? policy, ProjectConfig project, Random rng)
    {
        if (policy is null)
            return JokerEngine.ShouldPlay(project, rng);

        var chance = policy.JokerInvokeChance;
        if (chance <= 0)
            return false;
        return rng.NextDouble() < Math.Clamp(chance, 0, 1);
    }

    public static void PersistLast(HuntPolicyDecision policy, string project, int iteration, string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(project))
            return;

        var path = LastPolicyPath(project, repoRoot);
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        ScreamEvolutionTelemetryDto? evo = null;
        var index = ScreamFamilyIndex.TryLoad(project, repoRoot);
        if (index is not null)
            evo = ScreamFamilyIndex.ComputeTelemetry(index);

        var snap = new HuntPolicySnapshotDto(project, iteration, DateTimeOffset.UtcNow, policy, evo);
        File.WriteAllText(path, JsonSerializer.Serialize(snap, JsonOptions));
        HuntPolicyStore.SetLive(project, policy);
    }

    public static HuntPolicySnapshotDto? TryLoadSnapshot(string project, string? repoRoot = null)
    {
        var live = HuntPolicyStore.GetLive(project);
        if (live is not null)
            return new HuntPolicySnapshotDto(project, 0, DateTimeOffset.UtcNow, live);

        var path = LastPolicyPath(project, repoRoot);
        if (!File.Exists(path))
            return null;

        try
        {
            return JsonSerializer.Deserialize<HuntPolicySnapshotDto>(File.ReadAllText(path), JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    public static string FormatVerbose(HuntPolicyDecision policy)
    {
        if (policy.HuntValue <= 0 && policy.Mode == HuntExecutionMode.Baseline)
            return $"Hunt policy: {policy.Summary}";

        var terms = policy.Terms.Count == 0
            ? policy.Summary
            : string.Join(" · ", policy.Terms.Select(t =>
                t.Points >= 0 ? $"+{t.Points} {t.Label}" : $"{t.Points} {t.Label}"));

        var chain = policy.LineageChain is { Count: >= 2 }
            ? $" chain={string.Join('→', policy.LineageChain)}"
            : "";

        return
            $"Hunt policy: {policy.Mode} [{policy.HuntValue}] " +
            $"joker={policy.JokerInvokeChance:P0}{chain}" +
            (policy.NeedsExperiment ? " · needs-experiment" : "") +
            $" — {terms}";
    }

    private sealed record ScoredCandidate(RandallBrain.HuntCandidate Candidate, int Value, List<OracleScoreTerm> Terms);

    private static ScoredCandidate ScoreCandidate(RandallBrain.HuntCandidate candidate, Context ctx)
    {
        var terms = new List<OracleScoreTerm>(candidate.Terms);
        var value = candidate.Score;

        switch (candidate.Kind)
        {
            case "frontier":
                terms.Add(new OracleScoreTerm("frontier distance", Math.Min(18, candidate.Score / 4), candidate.Detail));
                value += Math.Min(12, candidate.Score / 6);
                ApplyOptionalGravityBoost(candidate, ctx, terms, ref value);
                break;
            case "gravity":
                terms.Add(new OracleScoreTerm("reachability pressure", Math.Min(20, candidate.Score / 4), candidate.Detail));
                value += Math.Min(14, candidate.Score / 5);
                break;
            case "static":
            case "patch":
                terms.Add(new OracleScoreTerm("static target", Math.Min(16, candidate.Score / 5), candidate.Kind));
                value += Math.Min(10, candidate.Score / 7);
                ApplyOptionalGravityBoost(candidate, ctx, terms, ref value);
                break;
            case "oracle":
                terms.Add(new OracleScoreTerm("oracle interestingness", Math.Min(20, candidate.Score / 4), candidate.Label));
                value += Math.Min(12, candidate.Score / 5);
                break;
            case "scream":
                ApplyScreamScoring(candidate, ctx, terms, ref value);
                break;
            case "mutator":
                terms.Add(new OracleScoreTerm("mutation success", Math.Min(14, candidate.Score / 6), candidate.Label));
                value += Math.Min(8, candidate.Score / 8);
                break;
        }

        var execCost = ComputeExecutionCost(candidate, ctx);
        if (execCost > 0)
        {
            terms.Add(new OracleScoreTerm("execution cost", -execCost, "low-ROI mutator history"));
            value -= execCost;
        }

        if (candidate.Kind == "scream")
        {
            var cluster = FindScreamCluster(candidate, ctx.Signals);
            if (cluster?.DebuggerInfluence > 0)
            {
                terms.Add(new OracleScoreTerm("debugger influence", cluster.DebuggerInfluence,
                    cluster.DebuggerExploitability ?? "debugger"));
                value += cluster.DebuggerInfluence;
            }
        }

        if (ctx.CoverageFraction >= 0.75 && candidate.Kind is "frontier" or "static")
        {
            var yieldPenalty = Math.Min(8, (int)Math.Round((ctx.CoverageFraction - 0.7) * 20));
            if (yieldPenalty > 0 && ctx.Signals.ScreamClusters.All(s => s.MomentumScore < 35))
            {
                terms.Add(new OracleScoreTerm("coverage exhaustion", -yieldPenalty, $"{ctx.CoverageFraction:P0} covered"));
                value -= yieldPenalty;
            }
        }

        value = Math.Max(1, value);
        return new ScoredCandidate(candidate, value, terms);
    }

    private static void ApplyOptionalGravityBoost(
        RandallBrain.HuntCandidate candidate,
        Context ctx,
        List<OracleScoreTerm> terms,
        ref int value)
    {
        var pressure = TargetGravityEngine.TryGetTopPressure(ctx.Project, ctx.RepoRoot);
        if (pressure is not { Score: >= 45 })
            return;

        var boost = Math.Min(10, pressure.Value.Score / 10);
        terms.Add(new OracleScoreTerm("target gravity", boost, pressure.Value.Label));
        value += boost;
    }

    private static void ApplyScreamScoring(
        RandallBrain.HuntCandidate candidate,
        Context ctx,
        List<OracleScoreTerm> terms,
        ref int value)
    {
        var cluster = FindScreamCluster(candidate, ctx.Signals);
        if (cluster is null)
            return;

        if (cluster.MomentumScore >= 40)
        {
            terms.Add(new OracleScoreTerm("crash progression", Math.Min(22, cluster.MomentumScore / 3),
                $"{cluster.MomentumLabel} momentum={cluster.MomentumScore}"));
            value += Math.Min(18, cluster.MomentumScore / 4);
        }

        if (cluster.Generation > 1)
        {
            terms.Add(new OracleScoreTerm("lineage generation", Math.Min(8, cluster.Generation), $"gen {cluster.Generation}"));
            value += Math.Min(6, cluster.Generation);
        }

        if (cluster.Saturated || cluster.IsStagnantNullDeref)
        {
            var dup = cluster.Saturated ? Math.Min(15, cluster.SeenCount) : Math.Min(12, cluster.SeenCount / 2);
            terms.Add(new OracleScoreTerm("duplicate penalty", -dup,
                cluster.IsStagnantNullDeref ? "stagnant NULL-deref" : "saturated cluster"));
            value -= dup;
        }
    }

    private static RandallBrain.ScreamClusterSignal? FindScreamCluster(
        RandallBrain.HuntCandidate candidate,
        RandallBrain.Signals signals) =>
        signals.ScreamClusters.FirstOrDefault(s =>
            string.Equals(s.Function ?? s.FamilyId ?? s.ClusterKey, candidate.Label, StringComparison.OrdinalIgnoreCase)
            || string.Equals(s.ClusterKey, candidate.Label, StringComparison.OrdinalIgnoreCase)
            || (s.FamilyId is not null && candidate.Label.Contains(s.FamilyId, StringComparison.OrdinalIgnoreCase)));

    private static int ComputeExecutionCost(RandallBrain.HuntCandidate candidate, Context ctx)
    {
        if (candidate.Kind != "mutator")
            return 0;

        var row = ctx.MutatorRows.FirstOrDefault(r =>
            r.Name.Equals(candidate.Label, StringComparison.OrdinalIgnoreCase));
        if (row is null)
            return 0;

        var stale = row.StaleRuns;
        var failRate = row.FailureRate;
        if (stale <= 2 && failRate < 0.85)
            return 0;

        return Math.Min(14, stale / 2 + (int)Math.Round(failRate * 6));
    }

    private static int ComputeExhaustionPenalty(Context ctx)
    {
        if (ctx.CoverageFraction < 0.65)
            return 0;

        var hot = ctx.Signals.ScreamClusters.Count(s => !s.Saturated && s.ScreamScore >= 50);
        var warming = ctx.Signals.ScreamClusters.Count(s => s.MomentumScore >= 40);
        if (hot > 0 || warming > 0)
            return 0;

        var productive = ctx.MutatorRows.Any(r => r.NewEdges >= 3 || r.UniqueCrashes > 0);
        if (productive)
            return 0;

        return ctx.CoverageFraction switch
        {
            >= 0.9 => -10,
            >= 0.8 => -7,
            _ => -4,
        };
    }

    private static HuntExecutionMode ResolveMode(
        ScoredCandidate top,
        Context ctx,
        int huntValue,
        IReadOnlyList<RandallBrain.ScreamClusterSignal> warming)
    {
        if (warming.Count > 0 && (top.Candidate.Kind == "scream" || warming.Any(w => w.MomentumScore >= 55)))
            return HuntExecutionMode.LineageBreed;

        if (top.Candidate.Kind is "frontier" or "patch" && huntValue >= 35)
            return HuntExecutionMode.HavocExplore;

        if (top.Candidate.Kind == "gravity" && huntValue >= 32)
            return HuntExecutionMode.HavocExplore;

        var stagnant = ctx.Signals.ScreamClusters.Count(s => s.Saturated || s.IsStagnantNullDeref);
        var lowYield = huntValue < 28 && ctx.CoverageFraction >= 0.5;
        if (lowYield || stagnant >= 2)
            return HuntExecutionMode.JokerInvoke;

        return HuntExecutionMode.Baseline;
    }

    private static string? ResolvePreferredMutator(
        RandallBrain.HuntCandidate top,
        Context ctx,
        HuntExecutionMode mode)
    {
        if (mode == HuntExecutionMode.LineageBreed)
        {
            var chain = ctx.ChainRows?.OrderByDescending(c => c.Score).FirstOrDefault();
            if (chain is not null && chain.Chain.Count >= 2)
                return ResolveMutatorName(ctx.Mutators, chain.Chain[^1]);
            return PickFirst(ctx.Mutators, "splice", "expand", "cyclic", "pattern", "havoc");
        }

        if (mode == HuntExecutionMode.HavocExplore)
            return PickFirst(ctx.Mutators, "havoc", "bitflip", "interesting", "splice");

        return top.Kind switch
        {
            "mutator" => ResolveMutatorName(ctx.Mutators, top.Label),
            "static" => PickFirst(ctx.Mutators, "dictionary", "havoc", "interesting"),
            "patch" => PickFirst(ctx.Mutators, "havoc", "bitflip", "interesting"),
            "frontier" => PickFirst(ctx.Mutators, "havoc", "splice", "bitflip"),
            "gravity" => PickFirst(ctx.Mutators, "havoc", "interesting", "dictionary", "splice"),
            "oracle" => PickFirst(ctx.Mutators, "interesting", "boundary", "havoc"),
            "scream" => PickFirst(ctx.Mutators, "cyclic", "pattern", "havoc", "expand"),
            _ => ctx.MutatorRows.FirstOrDefault()?.Name,
        };
    }

    private static IReadOnlyList<string>? ResolveLineageChain(
        Context ctx,
        HuntExecutionMode mode,
        string? preferredMutator)
    {
        if (mode != HuntExecutionMode.LineageBreed)
            return null;

        var warmingFamily = ctx.Signals.ScreamClusters
            .Where(s => s.MomentumScore >= 40 && !s.Saturated)
            .OrderByDescending(s => s.MomentumScore)
            .FirstOrDefault();

        var indexChain = ScreamFamilyIndex.BestLineageChain(ctx.Project ?? "", ctx.RepoRoot);
        if (indexChain is { Count: >= 2 })
            return indexChain;

        var chain = ctx.ChainRows?
            .Where(c => c.Chain.Count >= 2)
            .OrderByDescending(c => c.Score)
            .FirstOrDefault();

        if (chain is not null)
            return chain.Chain;

        if (preferredMutator is not null)
            return ["seed", preferredMutator];

        return warmingFamily is not null ? ["seed", "havoc"] : null;
    }

    private static double ResolveJokerChance(
        Context ctx,
        HuntExecutionMode mode,
        int huntValue,
        int exhaustion,
        int stagnantNull)
    {
        var baseChance = Math.Clamp(ctx.BaseJokerChance, 0, 1);
        if (baseChance <= 0 && mode != HuntExecutionMode.JokerInvoke)
            return 0;

        var chance = baseChance;

        if (mode == HuntExecutionMode.JokerInvoke)
            chance = Math.Max(chance, 0.18);

        if (exhaustion < -5)
            chance = Math.Max(chance, baseChance + 0.08);

        if (stagnantNull >= 2)
            chance = Math.Max(chance, baseChance + 0.06);

        if (mode == HuntExecutionMode.LineageBreed && huntValue >= 45)
            chance *= 0.55;

        if (ctx.Signals.ScreamClusters.Any(s => s.MomentumScore >= 55))
            chance *= 0.65;

        return Math.Clamp(chance, 0, 0.35);
    }

    private static (bool NeedsExperiment, string? Hint, HypothesisDto? Top) ResolveExperiment(
        Context ctx,
        RandallBrain.HuntCandidate top)
    {
        var project = ctx.Project;
        HypothesisDto? topHyp = null;
        if (!string.IsNullOrWhiteSpace(project))
            topHyp = HypothesisEngine.FindTopForProject(project, ctx.RepoRoot);

        var stalledWarm = ctx.Signals.ScreamClusters
            .FirstOrDefault(s => s.MomentumScore is >= 35 and < 50
                                 && s.Generation >= 2
                                 && !s.Saturated);

        if (topHyp is { ConfidencePercent: >= HypothesisEngine.MinExperimentConfidence })
        {
            var hint =
                $"Hypothesis {topHyp.Id} ({topHyp.ConfidencePercent}%): {topHyp.Statement} " +
                $"→ {topHyp.Experiment.Kind} ({topHyp.Experiment.Description})";
            return (true, hint, topHyp);
        }

        if (stalledWarm is not null)
        {
            return (true,
                $"Stalled warming family {stalledWarm.FamilyId ?? stalledWarm.ClusterKey} " +
                $"gen {stalledWarm.Generation} — hypothesis queue / TTD stub (Phase D live rewind)",
                topHyp);
        }

        if (top.Kind == "scream" && top.Score >= 60)
            return (false, null, topHyp);

        return (false, null, topHyp);
    }

    private static string BuildSummary(
        HuntExecutionMode mode,
        RandallBrain.HuntCandidate top,
        int huntValue,
        double jokerChance,
        string? preferredMutator)
    {
        var modeLabel = mode switch
        {
            HuntExecutionMode.LineageBreed => "breed lineage",
            HuntExecutionMode.HavocExplore => "havoc explore",
            HuntExecutionMode.JokerInvoke => "invoke Joker",
            _ => "baseline hunt",
        };

        return
            $"Hunt {modeLabel} → {top.Kind} {top.Label} [value={huntValue}]" +
            (preferredMutator is not null ? $" · mutator={preferredMutator}" : "") +
            (jokerChance > 0 ? $" · joker≤{jokerChance:P0}" : "");
    }

    private static string? PickFirst(IReadOnlyList<IMutator> mutators, params string[] names)
    {
        foreach (var name in names)
        {
            var resolved = ResolveMutatorName(mutators, name);
            if (resolved is not null)
                return resolved;
        }
        return null;
    }

    private static string? ResolveMutatorName(IReadOnlyList<IMutator> mutators, string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return null;
        return mutators.FirstOrDefault(m =>
            m.Name.Equals(name, StringComparison.OrdinalIgnoreCase))?.Name;
    }
}

/// <summary>In-process last hunt policy for live API during fuzz runs.</summary>
public static class HuntPolicyStore
{
    private static readonly object Gate = new();
    private static readonly Dictionary<string, HuntPolicyDecision> Live =
        new(StringComparer.OrdinalIgnoreCase);

    public static void SetLive(string project, HuntPolicyDecision policy)
    {
        lock (Gate)
            Live[project] = policy;
    }

    public static void Clear()
    {
        lock (Gate)
            Live.Clear();
    }

    public static HuntPolicyDecision? GetLive(string? project = null)
    {
        lock (Gate)
        {
            if (project is null)
                return Live.Values.FirstOrDefault();
            return Live.TryGetValue(project, out var p) ? p : null;
        }
    }
}
