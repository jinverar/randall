using System.Text.Json;
using Randall.Contracts;
using Randall.Core;
using Randall.Infrastructure.Magician;

namespace Randall.Infrastructure;

/// <summary>
/// Phase B Hunt Policy — campaign-ready: feedback weights, hysteresis, explicit actions.
/// </summary>
public static class HuntPolicyEngine
{
    public const string LastPolicyFileName = "hunt_policy_last.json";
    public const string WeightsFileName = "hunt_policy_weights.json";
    public const int FeedbackInterval = 25;
    public const int MutatorWeightFloor = MutatorCreditTracker.MinSelectionWeightFloor;

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
        string? RepoRoot = null,
        int ObservedNewEdges = 0,
        int ObservedUniqueCrashes = 0);

    public static string LastPolicyPath(string project, string? repoRoot = null) =>
        Path.Combine(StalkCampaignStore.ProjectDir(project, repoRoot), LastPolicyFileName);

    public static string WeightsPath(string project, string? repoRoot = null) =>
        Path.Combine(StalkCampaignStore.ProjectDir(project, repoRoot), WeightsFileName);

    public static HuntPolicyDecision Evaluate(Context ctx)
    {
        if (!ctx.Signals.HasData)
            return HuntPolicyDecision.Inactive();

        var candidates = RandallBrain.BuildCandidates(ctx.Signals, ctx.MutatorRows);
        if (candidates.Count == 0)
            return HuntPolicyDecision.Inactive();

        var project = ctx.Project ?? "";
        var weights = LoadOrCreateWeights(project, ctx.RepoRoot);
        var previousMode = string.IsNullOrWhiteSpace(project)
            ? null
            : TryLoadSnapshot(project, ctx.RepoRoot)?.Policy.Mode;
        var gravityReport = ctx.Signals.Gravity
            ?? (string.IsNullOrWhiteSpace(project) ? null : TargetGravityEngine.TryLoad(project, ctx.RepoRoot));
        var actions = new List<HuntPolicyAction>();

        var scored = candidates
            .Select(c => ScoreCandidate(c, ctx, weights.Weights, gravityReport, actions))
            .OrderByDescending(x => x.Value)
            .ThenBy(x => x.Candidate.Label, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var top = scored[0];
        var terms = ApplyTermWeights(top.Terms, top.Candidate.Kind, weights.Weights);

        var saturated = ctx.Signals.ScreamClusters.Count(s => s.Saturated);
        var stagnantNull = ctx.Signals.ScreamClusters.Count(s => s.IsStagnantNullDeref);
        if (saturated > 0)
        {
            terms.Add(new OracleScoreTerm("duplicate penalty", ScalePoints(-Math.Min(12, saturated * 3), weights.Weights.Scream),
                $"{saturated} saturated familie(s)"));
            actions.Add(new HuntPolicyAction(HuntPolicyActionKind.Deprioritize, "scream:saturated",
                $"{saturated} saturated familie(s)"));
        }

        if (stagnantNull > 0)
        {
            terms.Add(new OracleScoreTerm("null-deref stagnation", ScalePoints(-Math.Min(10, stagnantNull * 4), weights.Weights.Scream),
                $"{stagnantNull} READ-only familie(s)"));
            actions.Add(new HuntPolicyAction(HuntPolicyActionKind.Deprioritize, "scream:null-deref",
                $"{stagnantNull} stagnant NULL-deref familie(s)"));
        }

        var exhausted = ComputeExhaustionPenalty(ctx);
        if (exhausted < 0)
        {
            terms.Add(new OracleScoreTerm("exhaustion", exhausted, "high coverage · low yield"));
            actions.Add(new HuntPolicyAction(HuntPolicyActionKind.Reduce, "coverage:exhaustion",
                "high coverage with low scream/mutator yield"));
        }

        var warming = ctx.Signals.ScreamClusters.Where(s => s.MomentumScore >= 40 && !s.Saturated).ToList();
        if (warming.Count > 0 && top.Candidate.Kind != "scream")
        {
            terms.Add(new OracleScoreTerm("scream evolution", ScalePoints(Math.Min(14, warming.Count * 4), weights.Weights.Scream),
                $"{warming.Count} warming familie(s)"));
            actions.Add(new HuntPolicyAction(HuntPolicyActionKind.Boost, "scream:warming",
                $"{warming.Count} warming familie(s)"));
        }

        ApplyGravityAggregateTerms(gravityReport, terms, actions, weights.Weights);
        ApplyMutatorRoiActions(ctx, actions);

        var huntValue = Math.Clamp(terms.Sum(t => t.Points), 0, 100);
        var rawMode = ResolveRawMode(top, ctx, huntValue, warming);
        var mode = ApplyModeHysteresis(rawMode, previousMode, ctx, huntValue, warming, stagnantNull, actions);
        var preferredMutator = ResolvePreferredMutator(top.Candidate, ctx, mode);
        var lineageChain = ResolveLineageChain(ctx, mode, preferredMutator);
        var jokerChance = ResolveJokerChance(ctx, mode, huntValue, exhausted, stagnantNull);
        var (needsExperiment, experimentHint, topHypothesis) = ResolveExperiment(ctx, top.Candidate);

        var summary = BuildSummary(mode, top.Candidate, huntValue, jokerChance, preferredMutator);
        if (topHypothesis is not null && needsExperiment)
            summary += $" · hyp={topHypothesis.HypothesisTypeId}@{topHypothesis.Id} (support={topHypothesis.SupportScore})";

        return new HuntPolicyDecision(
            huntValue, mode, summary, jokerChance, needsExperiment, experimentHint, terms,
            top.Candidate.Kind, top.Candidate.Label, top.Candidate.Score, preferredMutator,
            lineageChain, topHypothesis?.Id, topHypothesis?.ConfidencePercent ?? 0, topHypothesis?.Statement,
            actions, weights.Weights, rawMode != mode ? rawMode : null);
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

    public static void PersistLast(
        HuntPolicyDecision policy,
        string project,
        int iteration,
        string? repoRoot = null,
        int observedNewEdges = 0,
        int observedUniqueCrashes = 0)
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
        AccumulateFeedbackAndMaybeAdapt(project, iteration, policy, repoRoot, observedNewEdges, observedUniqueCrashes);
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

    public static HuntPolicyWeightsDto LoadOrCreateWeights(string? project, string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(project))
            return new HuntPolicyWeightsDto("", 0, new HuntPolicyTermWeights());

        var path = WeightsPath(project, repoRoot);
        if (!File.Exists(path))
            return new HuntPolicyWeightsDto(project, 0, new HuntPolicyTermWeights());

        try
        {
            return JsonSerializer.Deserialize<HuntPolicyWeightsDto>(File.ReadAllText(path), JsonOptions)
                   ?? new HuntPolicyWeightsDto(project, 0, new HuntPolicyTermWeights());
        }
        catch
        {
            return new HuntPolicyWeightsDto(project, 0, new HuntPolicyTermWeights());
        }
    }

    public static string FormatVerbose(HuntPolicyDecision policy) =>
        FormatVerbose(policy, null, null);

    public static string FormatVerbose(HuntPolicyDecision policy, string? project, string? repoRoot)
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

        var actionLine = policy.Actions is { Count: > 0 }
            ? " · " + string.Join(" · ", policy.Actions.Select(a =>
                $"{a.Kind.ToString().ToLowerInvariant()}:{a.Target}"))
            : "";

        var hysteresis = policy.RawMode is not null && policy.RawMode != policy.Mode
            ? $" (raw={policy.RawMode})"
            : "";

        var evo = !string.IsNullOrWhiteSpace(project)
            ? ScreamFamilyIndex.ComputeTelemetry(ScreamFamilyIndex.TryLoad(project, repoRoot))
            : null;
        var evoSuffix = evo is { FamilyCount: > 0 }
            ? $" · evo {evo.WarmingFamilies}w/{evo.HotFamilies}h/{evo.StagnantFamilies}s"
            : "";

        return
            $"Hunt policy: {policy.Mode}{hysteresis} [{policy.HuntValue}] " +
            $"joker={policy.JokerInvokeChance:P0}{chain}{evoSuffix}" +
            (policy.NeedsExperiment ? " · needs-experiment" : "") +
            actionLine +
            $" — {terms}";
    }

    internal static int ScalePoints(int points, double weight) =>
        points == 0 ? 0 : (int)Math.Round(points * Math.Clamp(weight, HuntPolicyTermWeights.Min, HuntPolicyTermWeights.Max));

    internal static HuntExecutionMode ApplyModeHysteresis(
        HuntExecutionMode rawMode,
        HuntExecutionMode? previousMode,
        Context ctx,
        int huntValue,
        IReadOnlyList<RandallBrain.ScreamClusterSignal> warming,
        int stagnantNull,
        List<HuntPolicyAction> actions)
    {
        if (previousMode is null || previousMode == rawMode)
            return rawMode;

        if (previousMode == HuntExecutionMode.LineageBreed && rawMode == HuntExecutionMode.JokerInvoke)
        {
            var stagnant = ctx.Signals.ScreamClusters.Count(s => s.Saturated || s.IsStagnantNullDeref);
            if (huntValue >= 22 || stagnant < 3)
            {
                actions.Add(new HuntPolicyAction(HuntPolicyActionKind.Hold, "mode:LineageBreed",
                    "hysteresis — warming lineage still active"));
                return HuntExecutionMode.LineageBreed;
            }
        }

        if (previousMode == HuntExecutionMode.JokerInvoke && rawMode == HuntExecutionMode.LineageBreed)
        {
            if (!warming.Any(w => w.MomentumScore >= 52))
            {
                actions.Add(new HuntPolicyAction(HuntPolicyActionKind.Hold, "mode:JokerInvoke",
                    "hysteresis — no strong warming signal yet"));
                return HuntExecutionMode.JokerInvoke;
            }
        }

        if (previousMode == HuntExecutionMode.Baseline && rawMode == HuntExecutionMode.HavocExplore && huntValue < 42)
        {
            actions.Add(new HuntPolicyAction(HuntPolicyActionKind.Hold, "mode:Baseline",
                "hysteresis — frontier score below havoc threshold"));
            return HuntExecutionMode.Baseline;
        }

        if (previousMode == HuntExecutionMode.HavocExplore && rawMode == HuntExecutionMode.Baseline && huntValue >= 30)
        {
            actions.Add(new HuntPolicyAction(HuntPolicyActionKind.Hold, "mode:HavocExplore",
                "hysteresis — frontier pressure still elevated"));
            return HuntExecutionMode.HavocExplore;
        }

        return rawMode;
    }

    private sealed record ScoredCandidate(RandallBrain.HuntCandidate Candidate, int Value, List<OracleScoreTerm> Terms);

    private static ScoredCandidate ScoreCandidate(
        RandallBrain.HuntCandidate candidate,
        Context ctx,
        HuntPolicyTermWeights weights,
        TargetGravityReportDto? gravityReport,
        List<HuntPolicyAction> actions)
    {
        var categoryWeight = weights.ForCategory(candidate.Kind);
        var terms = new List<OracleScoreTerm>(candidate.Terms);
        var value = candidate.Score;

        switch (candidate.Kind)
        {
            case "frontier":
                terms.Add(new OracleScoreTerm("frontier distance", ScalePoints(Math.Min(18, candidate.Score / 4), weights.Frontier), candidate.Detail));
                value += ScalePoints(Math.Min(12, candidate.Score / 6), weights.Frontier);
                ApplyGravityBoost(candidate, ctx, gravityReport, terms, ref value, weights.Gravity, actions);
                break;
            case "gravity":
                terms.Add(new OracleScoreTerm("reachability pressure", ScalePoints(Math.Min(20, candidate.Score / 4), weights.Gravity), candidate.Detail));
                value += ScalePoints(Math.Min(14, candidate.Score / 5), weights.Gravity);
                ApplyStrongGravity(candidate, gravityReport, terms, ref value, weights.Gravity, actions);
                break;
            case "static":
            case "patch":
                terms.Add(new OracleScoreTerm("static target", ScalePoints(Math.Min(16, candidate.Score / 5), weights.Static), candidate.Kind));
                value += ScalePoints(Math.Min(10, candidate.Score / 7), weights.Static);
                ApplyGravityBoost(candidate, ctx, gravityReport, terms, ref value, weights.Gravity, actions);
                break;
            case "oracle":
                terms.Add(new OracleScoreTerm("oracle interestingness", ScalePoints(Math.Min(20, candidate.Score / 4), weights.Oracle), candidate.Label));
                value += ScalePoints(Math.Min(12, candidate.Score / 5), weights.Oracle);
                break;
            case "scream":
                ApplyScreamScoring(candidate, ctx, terms, ref value, weights.Scream);
                break;
            case "mutator":
                terms.Add(new OracleScoreTerm("mutation success", ScalePoints(Math.Min(14, candidate.Score / 6), weights.Mutator), candidate.Label));
                value += ScalePoints(Math.Min(8, candidate.Score / 8), weights.Mutator);
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
                terms.Add(new OracleScoreTerm("debugger influence", ScalePoints(cluster.DebuggerInfluence, weights.Scream),
                    cluster.DebuggerExploitability ?? "debugger"));
                value += ScalePoints(cluster.DebuggerInfluence, weights.Scream);
                actions.Add(new HuntPolicyAction(HuntPolicyActionKind.Boost,
                    $"scream:{cluster.FamilyId ?? cluster.ClusterKey}", "debugger influence"));
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

        return new ScoredCandidate(candidate, Math.Max(1, (int)Math.Round(value * categoryWeight)), terms);
    }

    private static void ApplyGravityBoost(
        RandallBrain.HuntCandidate candidate,
        Context ctx,
        TargetGravityReportDto? report,
        List<OracleScoreTerm> terms,
        ref int value,
        double gravityWeight,
        List<HuntPolicyAction> actions)
    {
        report ??= string.IsNullOrWhiteSpace(ctx.Project) ? null : TargetGravityEngine.TryLoad(ctx.Project, ctx.RepoRoot);
        if (report is null || report.WellCount == 0) return;
        var pressure = TargetGravityEngine.TryGetTopPressure(ctx.Project, ctx.RepoRoot);
        var threshold = report.AggregatePressure >= 50 ? 28 : 35;
        if (pressure is not { Score: var score } || score < threshold) return;
        var boost = ScalePoints(Math.Min(16, score / 6 + report.AggregatePressure / 25), gravityWeight);
        terms.Add(new OracleScoreTerm("target gravity", boost, pressure.Value.Label));
        value += boost;
        actions.Add(new HuntPolicyAction(HuntPolicyActionKind.Boost, $"gravity:{pressure.Value.Label}",
            $"target_gravity.json pressure {score}/100"));
    }

    private static void ApplyStrongGravity(
        RandallBrain.HuntCandidate candidate,
        TargetGravityReportDto? report,
        List<OracleScoreTerm> terms,
        ref int value,
        double gravityWeight,
        List<HuntPolicyAction> actions)
    {
        if (report is null || report.WellCount == 0) return;
        var well = report.Wells.FirstOrDefault(w =>
            string.Equals(w.SinkSymbol ?? w.FunctionName ?? w.Address ?? w.Kind, candidate.Label, StringComparison.OrdinalIgnoreCase));
        if (well is not null && well.GravityScore >= 30)
        {
            var extra = ScalePoints(Math.Min(10, well.GravityScore / 8), gravityWeight);
            terms.Add(new OracleScoreTerm("gravity well match", extra, well.Detail));
            value += extra;
        }
        if (report.AggregatePressure >= 40)
        {
            var agg = ScalePoints(Math.Min(8, report.AggregatePressure / 12), gravityWeight);
            terms.Add(new OracleScoreTerm("gravity aggregate", agg, $"aggregate {report.AggregatePressure}/100"));
            value += agg;
            actions.Add(new HuntPolicyAction(HuntPolicyActionKind.Boost, "gravity:aggregate",
                $"aggregate pressure {report.AggregatePressure}/100"));
        }
    }

    private static void ApplyScreamScoring(
        RandallBrain.HuntCandidate candidate,
        Context ctx,
        List<OracleScoreTerm> terms,
        ref int value,
        double screamWeight)
    {
        var cluster = FindScreamCluster(candidate, ctx.Signals);
        if (cluster is null)
            return;

        if (cluster.MomentumScore >= 40)
        {
            terms.Add(new OracleScoreTerm("crash progression", ScalePoints(Math.Min(22, cluster.MomentumScore / 3), screamWeight),
                $"{cluster.MomentumLabel} momentum={cluster.MomentumScore}"));
            value += ScalePoints(Math.Min(18, cluster.MomentumScore / 4), screamWeight);
        }

        if (cluster.Generation > 1)
        {
            terms.Add(new OracleScoreTerm("lineage generation", ScalePoints(Math.Min(8, cluster.Generation), screamWeight),
                $"gen {cluster.Generation}"));
            value += ScalePoints(Math.Min(6, cluster.Generation), screamWeight);
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

    private static HuntExecutionMode ResolveRawMode(
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

    private static List<OracleScoreTerm> ApplyTermWeights(List<OracleScoreTerm> terms, string focusKind, HuntPolicyTermWeights weights) =>
        terms.Select(t =>
        {
            var tw = weights.ForCategory(TermCategory(t.Label));
            return Math.Abs(tw - 1.0) < 0.001 ? t : new OracleScoreTerm(t.Label, ScalePoints(t.Points, tw), t.Detail);
        }).ToList();

    private static string TermCategory(string label)
    {
        var l = label.ToLowerInvariant();
        if (l.Contains("gravity") || l.Contains("reachability")) return "gravity";
        if (l.Contains("frontier")) return "frontier";
        if (l.Contains("scream") || l.Contains("crash") || l.Contains("lineage") || l.Contains("duplicate") || l.Contains("null-deref")) return "scream";
        if (l.Contains("oracle")) return "oracle";
        if (l.Contains("mutator") || l.Contains("mutation") || l.Contains("execution cost")) return "mutator";
        return "static";
    }

    private static void ApplyMutatorRoiActions(Context ctx, List<HuntPolicyAction> actions)
    {
        foreach (var row in ctx.MutatorRows)
        {
            if (row.StaleRuns <= 1 && row.FailureRate < 0.70) continue;
            if ((row.StaleRuns >= 3 || row.FailureRate >= 0.75)
                && !actions.Any(a => a.Target.Contains(row.Name, StringComparison.OrdinalIgnoreCase)))
                actions.Add(new HuntPolicyAction(HuntPolicyActionKind.Reduce, $"mutator:{row.Name}",
                    $"staleRuns={row.StaleRuns} failureRate={row.FailureRate:P0} (floor={MutatorWeightFloor})"));
            if (row.FailureRate >= 0.90 && row.StaleRuns >= 5
                && !actions.Any(a => a.Kind == HuntPolicyActionKind.Deprioritize && a.Target.Contains(row.Name, StringComparison.OrdinalIgnoreCase)))
                actions.Add(new HuntPolicyAction(HuntPolicyActionKind.Deprioritize, $"mutator:{row.Name}",
                    $"chronic failure {row.FailureRate:P0} over {row.Runs} runs"));
        }
    }

    private static void ApplyGravityAggregateTerms(TargetGravityReportDto? report, List<OracleScoreTerm> terms, List<HuntPolicyAction> actions, HuntPolicyTermWeights weights)
    {
        if (report is null || report.AggregatePressure < 55 || report.WellCount == 0) return;
        if (terms.Any(t => t.Label.Contains("gravity", StringComparison.OrdinalIgnoreCase))) return;
        var boost = ScalePoints(Math.Min(6, report.AggregatePressure / 15), weights.Gravity);
        terms.Add(new OracleScoreTerm("target gravity field", boost, $"{report.WellCount} well(s)"));
        actions.Add(new HuntPolicyAction(HuntPolicyActionKind.Boost, "gravity:field",
            $"strong target_gravity.json ({report.AggregatePressure}/100 aggregate)"));
    }

    private static void AccumulateFeedbackAndMaybeAdapt(string project, int iteration, HuntPolicyDecision policy, string? repoRoot, int observedNewEdges, int observedUniqueCrashes)
    {
        var dto = LoadOrCreateWeights(project, repoRoot);
        var window = dto.PendingWindow ?? new HuntPolicyFeedbackWindow(iteration, iteration, 0, 0, 0, 0, 0, 0, 0, 0);
        var predicted = SumPredictedByCategory(policy.Terms);
        window = window with
        {
            EndIteration = iteration,
            PredictedScream = window.PredictedScream + predicted.scream,
            PredictedGravity = window.PredictedGravity + predicted.gravity,
            PredictedFrontier = window.PredictedFrontier + predicted.frontier,
            PredictedStatic = window.PredictedStatic + predicted.static_,
            PredictedOracle = window.PredictedOracle + predicted.oracle,
            PredictedMutator = window.PredictedMutator + predicted.mutator,
            ObservedNewEdges = window.ObservedNewEdges + Math.Max(0, observedNewEdges),
            ObservedUniqueCrashes = window.ObservedUniqueCrashes + Math.Max(0, observedUniqueCrashes),
        };
        if (iteration - dto.LastAdaptIteration < FeedbackInterval)
        {
            SaveWeights(dto with { PendingWindow = window }, repoRoot);
            return;
        }
        var adapted = AdaptWeights(dto.Weights, window);
        var recent = (dto.RecentWindows ?? []).Prepend(window).Take(8).ToList();
        SaveWeights(new HuntPolicyWeightsDto(project, iteration, adapted, null, recent), repoRoot);
    }

    private static (double scream, double gravity, double frontier, double static_, double oracle, double mutator) SumPredictedByCategory(IReadOnlyList<OracleScoreTerm> terms)
    {
        double scream = 0, gravity = 0, frontier = 0, static_ = 0, oracle = 0, mutator = 0;
        foreach (var t in terms.Where(t => t.Points > 0))
            switch (TermCategory(t.Label))
            {
                case "scream": scream += t.Points; break;
                case "gravity": gravity += t.Points; break;
                case "frontier": frontier += t.Points; break;
                case "static": static_ += t.Points; break;
                case "oracle": oracle += t.Points; break;
                case "mutator": mutator += t.Points; break;
            }
        return (scream, gravity, frontier, static_, oracle, mutator);
    }

    private static HuntPolicyTermWeights AdaptWeights(HuntPolicyTermWeights current, HuntPolicyFeedbackWindow window)
    {
        var hadYield = window.ObservedNewEdges > 0 || window.ObservedUniqueCrashes > 0;
        var step = HuntPolicyTermWeights.AdaptStep;
        double Adapt(double weight, double predicted) =>
            predicted < 8 ? weight : hadYield ? Math.Min(HuntPolicyTermWeights.Max, weight + step) : Math.Max(HuntPolicyTermWeights.Min, weight - step);
        return new HuntPolicyTermWeights(
            Adapt(current.Scream, window.PredictedScream), Adapt(current.Gravity, window.PredictedGravity),
            Adapt(current.Frontier, window.PredictedFrontier), Adapt(current.Static, window.PredictedStatic),
            Adapt(current.Oracle, window.PredictedOracle), Adapt(current.Mutator, window.PredictedMutator)).Clamp();
    }

    private static void SaveWeights(HuntPolicyWeightsDto dto, string? repoRoot)
    {
        if (string.IsNullOrWhiteSpace(dto.Project)) return;
        var path = WeightsPath(dto.Project, repoRoot);
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllText(path, JsonSerializer.Serialize(dto, JsonOptions));
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
