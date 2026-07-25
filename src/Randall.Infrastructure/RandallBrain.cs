using System.Collections.Concurrent;
using System.Text.Json;
using Randall.Contracts;
using Randall.Core;
using Randall.Infrastructure.Oracles;

namespace Randall.Infrastructure;

/// <summary>
/// Fuses frontier, static fuzzPriority, oracle findings, mutator credit, and scream novelty
/// into explainable next-hunt decisions that steer seed/mutator/energy selection in <see cref="FuzzEngine"/>.
/// </summary>
public sealed class RandallBrain
{
    public const string LastDecisionFileName = "brain_last.json";

    private static readonly ConcurrentDictionary<string, (string Kind, string? Label, int Iteration)> LastJournaledBrain =
        new(StringComparer.OrdinalIgnoreCase);

    private const int BrainJournalEveryIterations = 25;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public sealed record Signals(
        bool HasData,
        string SummaryLine,
        FrontierReportDto? Frontier,
        GhidraAnalysisOracleHints.HintPack? StaticHints,
        RandallAnalysisDocument? Analysis,
        IReadOnlyList<OracleFindingDto> OracleFindings,
        IReadOnlyList<ScreamClusterSignal> ScreamClusters);

    public sealed record ScreamClusterSignal(
        string ClusterKey,
        int ScreamScore,
        int Novelty,
        int SeenCount,
        string? Function,
        bool Saturated);

    public sealed record HuntCandidate(
        string Kind,
        string Label,
        int Score,
        string Detail,
        IReadOnlyList<OracleScoreTerm> Terms);

    public static bool ShouldActivate(ProjectConfig project, Signals signals) =>
        project.Fuzz.Brain && signals.HasData;

    public static string LastDecisionPath(string project, string? repoRoot = null) =>
        Path.Combine(StalkCampaignStore.ProjectDir(project, repoRoot), LastDecisionFileName);

    public Signals LoadSignals(string project, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();

        var frontier = FrontierEngine.TryLoad(project, repoRoot);
        var analysis = GhidraAnalysisBridge.TryLoad(project, repoRoot);
        var hints = GhidraAnalysisOracleHints.TryBuild(project, repoRoot);
        var oracleFindings = LoadRecentOracleFindings(project, repoRoot, 8);
        var screams = LoadScreamSignals(project, repoRoot);

        var hasData = (frontier?.FrontierCount ?? 0) > 0
                      || hints is not null
                      || oracleFindings.Count > 0
                      || screams.Any(s => !s.Saturated && s.ScreamScore >= 40);

        var summaryLine = BuildSignalsSummary(frontier, hints, oracleFindings.Count, screams, hasData);
        return new Signals(hasData, summaryLine, frontier, hints, analysis, oracleFindings, screams);
    }

    public NextHuntDecision Decide(
        string project,
        Signals signals,
        IReadOnlyList<MutatorCreditRowDto> mutatorRows,
        IReadOnlyList<IMutator> mutators,
        int iteration)
    {
        if (!signals.HasData)
            return NextHuntDecision.Inactive(project, iteration);

        var candidates = BuildCandidates(signals, mutatorRows);
        if (candidates.Count == 0)
            return NextHuntDecision.Inactive(project, iteration);

        var top = candidates[0];
        var why = new List<OracleScoreTerm>(top.Terms);

        var preferredMutator = ResolvePreferredMutator(top, mutatorRows, signals, mutators);
        if (preferredMutator is not null)
            why.Add(new OracleScoreTerm("mutator pick", 6, preferredMutator));

        var saturated = signals.ScreamClusters.Count(s => s.Saturated);
        if (saturated > 0)
            why.Add(new OracleScoreTerm("scream saturation", -Math.Min(8, saturated * 2),
                $"{saturated} cluster(s) de-prioritized"));

        var hotScreams = signals.ScreamClusters.Count(s => !s.Saturated && s.ScreamScore >= 55);
        if (hotScreams > 0 && top.Kind != "scream")
            why.Add(new OracleScoreTerm("scream novelty", Math.Min(10, hotScreams * 3),
                $"{hotScreams} hot cluster(s)"));

        if (mutatorRows.Count > 0)
        {
            var lead = mutatorRows[0];
            why.Add(new OracleScoreTerm("mutator credit", Math.Min(12, lead.SelectionWeight),
                $"{lead.Name} weight={lead.SelectionWeight}"));
        }

        var corpusBias = ResolveCorpusBias(top, signals);
        var energyBoost = ResolveEnergyBoost(top, signals);

        var total = Math.Clamp(why.Sum(t => t.Points), 0, 100);
        var breakdown = new OracleScore(total, why, top.Detail);
        var summary =
            $"Randall thinks: {top.Kind} → {top.Label} [{top.Score}]" +
            (preferredMutator is not null ? $" · mutator={preferredMutator}" : "") +
            $" · corpus={corpusBias:P0} energy+{energyBoost}";

        return new NextHuntDecision(
            iteration,
            DateTimeOffset.UtcNow,
            project,
            true,
            summary,
            top.Kind,
            top.Label,
            top.Score,
            preferredMutator,
            corpusBias,
            energyBoost,
            why,
            breakdown);
    }

    public IMutator PickMutator(
        NextHuntDecision decision,
        IReadOnlyList<IMutator> mutators,
        MutatorCreditTracker credit,
        Random rng)
    {
        if (mutators.Count == 0)
            throw new InvalidOperationException("No mutators available.");
        if (mutators.Count == 1)
            return mutators[0];

        if (!decision.Active || string.IsNullOrWhiteSpace(decision.PreferredMutator))
            return credit.Pick(mutators, rng);

        var preferred = mutators.FirstOrDefault(m =>
            m.Name.Equals(decision.PreferredMutator, StringComparison.OrdinalIgnoreCase));
        if (preferred is null)
            return credit.Pick(mutators, rng);

        // 62% brain preference, 38% credit roulette — keeps exploration alive.
        if (rng.NextDouble() < 0.62)
            return preferred;
        return credit.Pick(mutators, rng);
    }

    public void PersistLast(NextHuntDecision decision, string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(decision.Project))
            return;

        var path = LastDecisionPath(decision.Project, repoRoot);
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        var snapshot = BrainDecisionSnapshotDto.FromDecision(decision, decision.Project);
        File.WriteAllText(path, JsonSerializer.Serialize(snapshot, JsonOptions));
        BrainDecisionStore.SetLive(decision);

        if (decision.Active && ShouldJournalBrainDecision(decision))
        {
            try
            {
                TargetIntelligenceWriteBack.RecordBrainDecision(
                    decision.Project,
                    $"{decision.FocusKind}:{decision.FocusLabel}",
                    decision.Summary,
                    new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["focusKind"] = decision.FocusKind,
                        ["focusLabel"] = decision.FocusLabel,
                        ["focusScore"] = decision.FocusScore,
                        ["preferredMutator"] = decision.PreferredMutator,
                        ["iteration"] = decision.Iteration,
                    },
                    repoRoot);
            }
            catch { /* journal must not break brain persist */ }
        }
    }

    private static bool ShouldJournalBrainDecision(NextHuntDecision decision)
    {
        var key = decision.Project;
        if (decision.Iteration <= 1)
        {
            LastJournaledBrain[key] = (decision.FocusKind, decision.FocusLabel, decision.Iteration);
            return true;
        }

        if (decision.Iteration % BrainJournalEveryIterations == 0)
        {
            LastJournaledBrain[key] = (decision.FocusKind, decision.FocusLabel, decision.Iteration);
            return true;
        }

        if (LastJournaledBrain.TryGetValue(key, out var last)
            && last.Kind.Equals(decision.FocusKind, StringComparison.OrdinalIgnoreCase)
            && string.Equals(last.Label, decision.FocusLabel, StringComparison.OrdinalIgnoreCase))
            return false;

        LastJournaledBrain[key] = (decision.FocusKind, decision.FocusLabel, decision.Iteration);
        return true;
    }

    public static BrainDecisionSnapshotDto? TryLoadSnapshot(string project, string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(project))
            return null;

        var live = BrainDecisionStore.GetLive(project);
        if (live is not null)
        {
            return BrainDecisionSnapshotDto.FromDecision(live, project);
        }

        var path = LastDecisionPath(project, repoRoot);
        if (!File.Exists(path))
            return null;

        try
        {
            var snap = JsonSerializer.Deserialize<BrainDecisionSnapshotDto>(File.ReadAllText(path), JsonOptions);
            if (snap?.LastDecision is not null && snap.Decision is null)
                return BrainDecisionSnapshotDto.FromDecision(snap.LastDecision, snap.Project, snap.Enabled, snap.EmptyHint);
            return snap;
        }
        catch
        {
            return null;
        }
    }

    public static string FormatVerbose(NextHuntDecision decision)
    {
        if (!decision.Active)
            return $"Brain: idle — {decision.Summary}";

        var terms = decision.WhyTerms.Count == 0
            ? decision.ScoreBreakdown.Summary
            : string.Join(" · ", decision.WhyTerms.Select(t =>
                t.Points >= 0 ? $"+{t.Points} {t.Label}" : $"{t.Points} {t.Label}"));

        return
            $"Brain: {decision.FocusKind} {decision.FocusLabel} [{decision.FocusScore}] " +
            $"mutator={(decision.PreferredMutator ?? "credit")} " +
            $"corpus={decision.CorpusPriorityBias:P0} energy+{decision.RecommendedEnergyBoost} — {terms}";
    }

    internal static IReadOnlyList<HuntCandidate> BuildCandidates(
        Signals signals,
        IReadOnlyList<MutatorCreditRowDto> mutatorRows)
    {
        var list = new List<HuntCandidate>();

        if (signals.Frontier?.Frontiers is { Count: > 0 } frontiers)
        {
            var frontierBoost = FrontierRichnessBoost(signals);
            foreach (var f in frontiers.Take(4))
            {
                var score = f.Score + frontierBoost;
                list.Add(new HuntCandidate(
                    "frontier",
                    LabelFrontier(f),
                    score,
                    f.Detail,
                    BuildFrontierTerms(f, frontierBoost)));
            }
        }

        if (signals.StaticHints is not null)
        {
            foreach (var fn in signals.StaticHints.TopUncoveredTargets.Take(3))
            {
                list.Add(new HuntCandidate(
                    "static",
                    fn.Name,
                    fn.FuzzPriority,
                    $"priority {fn.FuzzPriority}/100 · {fn.UncoveredBlockCount} uncovered BB(s)",
                    BuildStaticTerms(fn, signals.Analysis)));
            }

            foreach (var fn in signals.StaticHints.TopChangedFunctions.Take(2))
            {
                list.Add(new HuntCandidate(
                    "patch",
                    fn.Name,
                    ScoreChangedFunction(fn),
                    $"{fn.ChangeKind} · priority Δ{fn.FuzzPriorityDelta:+0;-0}",
                    BuildPatchTerms(fn)));
            }
        }

        foreach (var finding in signals.OracleFindings.Take(4))
        {
            var score = ScoreOracleFinding(finding);
            list.Add(new HuntCandidate(
                "oracle",
                finding.RuleId,
                score,
                $"{finding.RuleClass} · {finding.Severity}",
                BuildOracleTerms(finding, score)));
        }

        foreach (var scream in signals.ScreamClusters
                     .Where(s => !s.Saturated && s.ScreamScore >= 40)
                     .OrderByDescending(s => s.ScreamScore)
                     .Take(3))
        {
            list.Add(new HuntCandidate(
                "scream",
                scream.Function ?? scream.ClusterKey,
                scream.ScreamScore,
                $"novelty {scream.Novelty}/100 · seen×{scream.SeenCount}",
                BuildScreamTerms(scream)));
        }

        if (mutatorRows.Count > 0)
        {
            var lead = mutatorRows[0];
            if (lead.SelectionWeight >= 3)
            {
                list.Add(new HuntCandidate(
                    "mutator",
                    lead.Name,
                    Math.Min(75, (int)Math.Round(lead.Score / Math.Max(1, lead.Runs)) + lead.SelectionWeight * 4),
                    $"weight={lead.SelectionWeight} edges={lead.NewEdges}",
                    [
                        new OracleScoreTerm("mutator credit", lead.SelectionWeight, lead.Name),
                        new OracleScoreTerm("productive edges", Math.Min(15, lead.NewEdges), $"{lead.NewEdges} edges"),
                    ]));
            }
        }

        return list
            .OrderByDescending(c => c.Score)
            .ThenBy(c => c.Label, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string? ResolvePreferredMutator(
        HuntCandidate top,
        IReadOnlyList<MutatorCreditRowDto> mutatorRows,
        Signals signals,
        IReadOnlyList<IMutator> mutators)
    {
        if (top.Kind == "mutator")
            return ResolveMutatorName(mutators, top.Label);

        var creditLead = mutatorRows.FirstOrDefault();
        if (creditLead is not null && creditLead.SelectionWeight >= 5 && top.Score <= creditLead.SelectionWeight * 8)
            return ResolveMutatorName(mutators, creditLead.Name);

        var pick = top.Kind switch
        {
            "static" => PickFirst(mutators, "dictionary", "havoc", "interesting"),
            "patch" => PickFirst(mutators, "havoc", "bitflip", "interesting"),
            "frontier" => PickFirst(mutators, "havoc", "splice", "bitflip"),
            "oracle" => PickFirst(mutators, "interesting", "boundary", "havoc"),
            "scream" => PickFirst(mutators, "cyclic", "pattern", "havoc", "expand"),
            _ => creditLead?.Name,
        };
        return ResolveMutatorName(mutators, pick);
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

    private static double ResolveCorpusBias(HuntCandidate top, Signals signals)
    {
        var bias = top.Kind switch
        {
            "frontier" => 0.82,
            "static" => 0.78,
            "patch" => 0.76,
            "oracle" => 0.72,
            "scream" => 0.70,
            "mutator" => 0.68,
            _ => 0.65,
        };

        if (top.Kind == "frontier" && FrontierRichnessBoost(signals) >= 10)
            bias = Math.Min(0.88, bias + 0.04);

        return bias;
    }

    private static int ResolveEnergyBoost(HuntCandidate top, Signals signals)
    {
        var boost = top.Kind switch
        {
            "frontier" => 4,
            "static" => 3,
            "patch" => 5,
            "oracle" => 4,
            "scream" => 3,
            _ => 2,
        };

        if (signals.StaticHints?.CoverageSummary is { CoverageFraction: < 0.5 })
            boost += 1;

        return Math.Clamp(boost, 0, 8);
    }

    private static string BuildSignalsSummary(
        FrontierReportDto? frontier,
        GhidraAnalysisOracleHints.HintPack? hints,
        int oracleCount,
        IReadOnlyList<ScreamClusterSignal> screams,
        bool hasData)
    {
        if (!hasData)
            return "no stalk/scream signals — brain will no-op";

        var parts = new List<string>();
        if (frontier?.FrontierCount > 0)
            parts.Add($"{frontier.FrontierCount} gray door(s)");
        if (hints is not null)
            parts.Add("static map");
        if (oracleCount > 0)
            parts.Add($"{oracleCount} oracle hint(s)");
        var hot = screams.Count(s => !s.Saturated && s.ScreamScore >= 40);
        if (hot > 0)
            parts.Add($"{hot} hot scream(s)");
        return string.Join(" · ", parts);
    }

    private static IReadOnlyList<ScreamClusterSignal> LoadScreamSignals(string project, string repoRoot)
    {
        var crashes = CrashCatalog.ListAll(repoRoot)
            .Where(c => c.Project.Equals(project, StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (crashes.Count == 0)
            return [];

        var byCluster = crashes
            .GroupBy(c => c.ClusterKey ?? c.Id.ToString(), StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                var lead = g.OrderByDescending(c => c.ScreamScore).First();
                var seen = g.Count();
                var novelty = lead.Novelty > 0 ? lead.Novelty : Math.Max(0, 100 - seen * 8);
                var screamScore = lead.ScreamScore;
                var saturated = seen >= 8 && novelty < 35;
                return new ScreamClusterSignal(
                    g.Key,
                    screamScore,
                    novelty,
                    seen,
                    lead.StaticFunctionSummary,
                    saturated);
            })
            .OrderByDescending(s => s.ScreamScore)
            .ToList();

        return byCluster;
    }

    private static IReadOnlyList<OracleFindingDto> LoadRecentOracleFindings(string project, string repoRoot, int limit)
    {
        var crashesRoot = Path.Combine(repoRoot, "data", "crashes", project, "_oracles");
        if (!Directory.Exists(crashesRoot))
            return [];

        var store = new OracleFindingStore(crashesRoot);
        return store.List(project)
            .OrderByDescending(f => f.At)
            .Take(limit)
            .ToList();
    }

    private static string LabelFrontier(FrontierBranchDto f) =>
        f.Kind switch
        {
            "session-fork" => $"Session fork → {f.ToAddress}",
            "edge-gap" => $"Edge gap → {f.ToAddress}",
            _ => string.IsNullOrWhiteSpace(f.FunctionName)
                ? $"Gray door → {f.ToAddress}"
                : $"{f.FunctionName} → {f.ToAddress}",
        };

    private static int FrontierRichnessBoost(Signals signals)
    {
        var frontier = signals.Frontier;
        if (frontier is null || frontier.FrontierCount < 3)
            return 0;

        var topScore = frontier.Frontiers.Count > 0
            ? frontier.Frontiers.Max(f => f.Score)
            : 0;

        if (frontier.FrontierCount >= 8 && topScore >= 70)
            return 15;
        if (frontier.FrontierCount >= 5 && topScore >= 60)
            return 10;
        return 5;
    }

    private static IReadOnlyList<OracleScoreTerm> BuildFrontierTerms(FrontierBranchDto f, int richnessBoost = 0)
    {
        var terms = new List<OracleScoreTerm> { new("frontier rank", f.Score, f.Kind) };
        if (richnessBoost > 0)
            terms.Add(new OracleScoreTerm("frontier richness", richnessBoost,
                $"{f.Score + richnessBoost} boosted"));
        if (f.UnseenSuccessorCount > 0)
            terms.Add(new OracleScoreTerm("unseen successors", Math.Min(12, f.UnseenSuccessorCount * 3),
                $"{f.UnseenSuccessorCount}"));
        if (f.SinkProximity > 0)
            terms.Add(new OracleScoreTerm("sink proximity", Math.Min(12, (int)Math.Round(f.SinkProximity * 12)),
                $"{f.SinkProximity:P0}"));
        return terms;
    }

    private static IReadOnlyList<OracleScoreTerm> BuildStaticTerms(
        RandallAnalysisFunctionDto fn,
        RandallAnalysisDocument? analysis)
    {
        var terms = new List<OracleScoreTerm>
        {
            new("fuzz priority", fn.FuzzPriority, $"{fn.FuzzPriority}/100"),
        };
        if (fn.UncoveredBlockCount > 0)
            terms.Add(new OracleScoreTerm("coverage gap", Math.Min(16, fn.UncoveredBlockCount * 3),
                $"{fn.UncoveredBlockCount} BB(s)"));
        var bonus = GhidraAnalysisOracleHints.StaticMapScoreBonus(fn.Name, analysis);
        if (bonus > 0)
            terms.Add(new OracleScoreTerm("static map bias", bonus, fn.Name));
        return terms;
    }

    private static IReadOnlyList<OracleScoreTerm> BuildPatchTerms(RandallAnalysisChangedFunctionDto fn) =>
    [
        new("change score", Math.Min(20, (int)Math.Round(fn.ChangeScore * 6)), fn.ChangeKind),
        new("priority delta", Math.Min(10, Math.Abs(fn.FuzzPriorityDelta)), $"{fn.FuzzPriorityDelta:+0;-0}"),
    ];

    private static IReadOnlyList<OracleScoreTerm> BuildOracleTerms(OracleFindingDto f, int score) =>
    [
        new("oracle hint", score, f.RuleId),
        new("rule class", 8, f.RuleClass),
    ];

    private static IReadOnlyList<OracleScoreTerm> BuildScreamTerms(ScreamClusterSignal scream) =>
    [
        new("scream score", Math.Min(40, scream.ScreamScore / 2), $"{scream.ScreamScore}"),
        new("novelty", Math.Min(20, scream.Novelty / 5), $"{scream.Novelty}/100"),
        new("cluster size", scream.SeenCount <= 1 ? 12 : -Math.Min(10, scream.SeenCount), $"seen×{scream.SeenCount}"),
    ];

    private static int ScoreChangedFunction(RandallAnalysisChangedFunctionDto fn) =>
        Math.Clamp((int)Math.Round(fn.ChangeScore * 10) + Math.Abs(fn.FuzzPriorityDelta), 20, 95);

    private static int ScoreOracleFinding(OracleFindingDto f) =>
        f.Severity.Trim().ToLowerInvariant() switch
        {
            "violation" => 85,
            "runtime" => 70,
            "nearmiss" or "near_miss" or "near-miss" => 45,
            _ => 25,
        };
}

/// <summary>In-process last brain decision for live API during fuzz runs.</summary>
public static class BrainDecisionStore
{
    private static readonly object Gate = new();
    private static NextHuntDecision? _live;

    public static void SetLive(NextHuntDecision decision)
    {
        lock (Gate)
            _live = decision;
    }

    public static void Clear()
    {
        lock (Gate)
            _live = null;
    }

    public static NextHuntDecision? GetLive(string? project = null)
    {
        lock (Gate)
        {
            if (_live is null)
                return null;
            if (project is not null &&
                !_live.Project.Equals(project, StringComparison.OrdinalIgnoreCase))
                return null;
            return _live;
        }
    }
}
