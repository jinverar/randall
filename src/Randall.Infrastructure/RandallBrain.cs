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
    public const string FocusFileName = "brain_focus.json";

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
        IReadOnlyList<ScreamClusterSignal> ScreamClusters,
        TargetGravityReportDto? Gravity = null);

    public sealed record ScreamClusterSignal(
        string ClusterKey,
        int ScreamScore,
        int Novelty,
        int SeenCount,
        string? Function,
        bool Saturated,
        int MomentumScore = 0,
        string? MomentumLabel = null,
        int Generation = 0,
        string? FamilyId = null,
        ScreamProgressionStep ProgressionStep = ScreamProgressionStep.Unknown,
        int DebuggerInfluence = 0,
        string? DebuggerExploitability = null)
    {
        /// <summary>Repeated READ-only NULL-deref family with low momentum — duplicate penalty target.</summary>
        public bool IsStagnantNullDeref =>
            ProgressionStep == ScreamProgressionStep.ReadViolation
            && MomentumScore < 35
            && SeenCount >= 4
            && Novelty < 40;
    }

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

    public static string FocusPath(string project, string? repoRoot = null) =>
        Path.Combine(StalkCampaignStore.ProjectDir(project, repoRoot), FocusFileName);

    public Signals LoadSignals(string project, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();

        var frontier = FrontierEngine.TryLoad(project, repoRoot);
        var gravity = TargetGravityEngine.TryLoad(project, repoRoot)
                      ?? TargetGravityEngine.Score(project, repoRoot, limit: 20, persist: true);
        var analysis = GhidraAnalysisBridge.TryLoad(project, repoRoot);
        var hints = GhidraAnalysisOracleHints.TryBuild(project, repoRoot);
        var oracleFindings = LoadRecentOracleFindings(project, repoRoot, 8);
        var screams = LoadScreamSignals(project, repoRoot);

        var hasData = (frontier?.FrontierCount ?? 0) > 0
                      || (gravity?.WellCount ?? 0) > 0
                      || hints is not null
                      || oracleFindings.Count > 0
                      || screams.Any(s => !s.Saturated && s.ScreamScore >= 40);

        var summaryLine = BuildSignalsSummary(frontier, gravity, hints, oracleFindings.Count, screams, hasData);
        return new Signals(hasData, summaryLine, frontier, hints, analysis, oracleFindings, screams, gravity);
    }

    public NextHuntDecision Decide(
        string project,
        Signals signals,
        IReadOnlyList<MutatorCreditRowDto> mutatorRows,
        IReadOnlyList<IMutator> mutators,
        int iteration,
        string? repoRoot = null,
        IReadOnlyList<MutatorChainRowDto>? chainRows = null,
        double memoryConfidence = 1.0,
        double coverageFraction = 0,
        double baseJokerChance = 0)
    {
        memoryConfidence = Math.Clamp(memoryConfidence, 0.05, 1.0);
        if (!signals.HasData)
            return NextHuntDecision.Inactive(project, iteration);

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();

        var huntPolicy = HuntPolicyEngine.Evaluate(new HuntPolicyEngine.Context(
            signals, mutatorRows, chainRows, mutators, coverageFraction, iteration,
            memoryConfidence, baseJokerChance, project, repoRoot));

        var candidates = BuildCandidates(signals, mutatorRows);
        var focus = TryLoadFocus(project, repoRoot);
        if (focus is not null)
            candidates = ApplyFocusPreference(candidates, focus, signals).ToList();
        if (memoryConfidence < 0.999)
            candidates = ApplyMemoryConfidence(candidates, memoryConfidence);

        if (candidates.Count == 0)
            return NextHuntDecision.Inactive(project, iteration);

        var top = candidates[0];

        var why = new List<OracleScoreTerm>(top.Terms);
        foreach (var term in huntPolicy.Terms)
        {
            if (!why.Any(t => t.Label.Equals(term.Label, StringComparison.OrdinalIgnoreCase)))
                why.Add(term);
        }

        var preferredMutator = huntPolicy.Mode is HuntExecutionMode.LineageBreed or HuntExecutionMode.HavocExplore
            ? huntPolicy.PreferredMutator ?? ResolvePreferredMutator(top, mutatorRows, signals, mutators, chainRows, huntPolicy)
            : ResolvePreferredMutator(top, mutatorRows, signals, mutators, chainRows, huntPolicy);
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

        var warmingFamilies = signals.ScreamClusters.Count(s => s.MomentumScore >= 40);
        if (warmingFamilies > 0)
            why.Add(new OracleScoreTerm("scream evolution", Math.Min(12, warmingFamilies * 4),
                $"{warmingFamilies} warming familie(s)"));

        if (mutatorRows.Count > 0)
        {
            var lead = mutatorRows[0];
            why.Add(new OracleScoreTerm("mutator credit", Math.Min(12, lead.SelectionWeight),
                $"{lead.Name} weight={lead.SelectionWeight}"));
        }

        if (chainRows is { Count: > 0 })
        {
            var topChain = chainRows[0];
            why.Add(new OracleScoreTerm("mutator chain", Math.Min(8, topChain.SelectionWeight),
                topChain.DisplayLabel));
        }

        if (memoryConfidence < 0.999)
        {
            why.Add(new OracleScoreTerm(
                "memory confidence",
                (int)Math.Round((memoryConfidence - 1.0) * 20),
                $"{memoryConfidence:P0} after target change"));
        }

        var corpusBias = ResolveCorpusBias(top, signals);
        var energyBoost = ResolveEnergyBoost(top, signals);

        var total = Math.Clamp(why.Sum(t => t.Points), 0, 100);
        var breakdown = new OracleScore(total, why, top.Detail);
        var summary =
            $"Randall thinks: {top.Kind} → {top.Label} [{top.Score}]" +
            (focus is not null ? " · pinned focus" : "") +
            (preferredMutator is not null ? $" · mutator={preferredMutator}" : "") +
            (memoryConfidence < 0.999 ? $" · memory={memoryConfidence:P0}" : "") +
            $" · corpus={corpusBias:P0} energy+{energyBoost}" +
            (huntPolicy.Mode != HuntExecutionMode.Baseline ? $" · hunt={huntPolicy.Mode}" : "");

        HuntPolicyEngine.PersistLast(huntPolicy, project, iteration, repoRoot);

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
            breakdown,
            huntPolicy);
    }

    public IMutator PickMutator(
        NextHuntDecision decision,
        IReadOnlyList<IMutator> mutators,
        MutatorCreditTracker credit,
        Random rng,
        MutatorChainTracker? chains = null,
        string? previousMutator = null)
    {
        if (mutators.Count == 0)
            throw new InvalidOperationException("No mutators available.");
        if (mutators.Count == 1)
            return mutators[0];

        var policy = decision.HuntPolicy;
        if (policy?.Mode == HuntExecutionMode.LineageBreed && chains is not null && chains.BiasEnabled)
        {
            if (policy.LineageChain is { Count: >= 2 })
            {
                var tail = policy.LineageChain[^1];
                var lineageMutator = mutators.FirstOrDefault(m =>
                    m.Name.Equals(tail, StringComparison.OrdinalIgnoreCase));
                if (lineageMutator is not null && rng.NextDouble() < 0.72)
                    return lineageMutator;
            }

            if (!string.IsNullOrWhiteSpace(previousMutator) && rng.NextDouble() < 0.55)
                return chains.BlendPick(mutators, credit, previousMutator, rng);
        }

        if (policy?.Mode == HuntExecutionMode.HavocExplore)
        {
            var havoc = mutators.FirstOrDefault(m => m.Name.Equals("havoc", StringComparison.OrdinalIgnoreCase));
            if (havoc is not null && rng.NextDouble() < 0.58)
                return havoc;
        }

        if (!decision.Active || string.IsNullOrWhiteSpace(decision.PreferredMutator))
            return PickWithOptionalChain(credit, chains, previousMutator, mutators, rng, policy);

        var preferred = mutators.FirstOrDefault(m =>
            m.Name.Equals(decision.PreferredMutator, StringComparison.OrdinalIgnoreCase));
        if (preferred is null)
            return PickWithOptionalChain(credit, chains, previousMutator, mutators, rng, policy);

        var preferChance = policy?.Mode == HuntExecutionMode.LineageBreed ? 0.74
            : policy?.Mode == HuntExecutionMode.HavocExplore ? 0.68
            : 0.62;

        if (rng.NextDouble() < preferChance)
        {
            if (chains is not null && chains.BiasEnabled && !string.IsNullOrWhiteSpace(previousMutator)
                && policy?.Mode != HuntExecutionMode.HavocExplore
                && rng.NextDouble() < 0.08)
            {
                var chainPick = chains.BlendPick(mutators, credit, previousMutator, rng);
                if (!chainPick.Name.Equals(preferred.Name, StringComparison.OrdinalIgnoreCase))
                    return chainPick;
            }
            return preferred;
        }

        return PickWithOptionalChain(credit, chains, previousMutator, mutators, rng, policy);
    }

    private static IMutator PickWithOptionalChain(
        MutatorCreditTracker credit,
        MutatorChainTracker? chains,
        string? previousMutator,
        IReadOnlyList<IMutator> mutators,
        Random rng,
        HuntPolicyDecision? policy = null) =>
        chains is not null && chains.BiasEnabled
            && policy?.Mode == HuntExecutionMode.LineageBreed
            && !string.IsNullOrWhiteSpace(previousMutator)
            ? chains.BlendPick(mutators, credit, previousMutator, rng)
            : chains is not null && chains.BiasEnabled
                ? chains.BlendPick(mutators, credit, previousMutator, rng)
                : credit.Pick(mutators, rng, policy);

    private static List<HuntCandidate> ApplyMemoryConfidence(IReadOnlyList<HuntCandidate> candidates, double factor)
    {
        if (factor >= 0.999) return candidates.ToList();
        return candidates.Select(c => new HuntCandidate(c.Kind, c.Label, Math.Max(1, (int)Math.Round(c.Score * factor)), c.Detail,
            c.Terms.Select(t => new OracleScoreTerm(t.Label, (int)Math.Round(t.Points * factor), t.Detail)).ToList()))
            .OrderByDescending(c => c.Score).ThenBy(c => c.Label, StringComparer.OrdinalIgnoreCase).ToList();
    }


    public void PersistLast(NextHuntDecision decision, string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(decision.Project))
            return;

        var path = LastDecisionPath(decision.Project, repoRoot);
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        var memory = BrainMemoryDecay.TryLoad(decision.Project, repoRoot);
        var screamTelemetry = ScreamFamilyIndex.ComputeTelemetry(
            ScreamFamilyIndex.TryLoad(decision.Project, repoRoot));
        var snapshot = BrainDecisionSnapshotDto.FromDecision(decision, decision.Project,
            memoryConfidence: memory?.MemoryConfidence ?? 1.0, memoryMessage: memory?.DecayMessage,
            screamEvolution: screamTelemetry);
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

    public static BrainFocusDto PersistFocus(
        string project,
        string focusKind,
        string focusLabel,
        string? address = null,
        string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(project))
            throw new ArgumentException("project required");
        if (string.IsNullOrWhiteSpace(focusKind))
            throw new ArgumentException("focusKind required");
        if (string.IsNullOrWhiteSpace(focusLabel))
            throw new ArgumentException("focusLabel required");

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var focus = new BrainFocusDto(
            project.Trim(),
            DateTimeOffset.UtcNow,
            focusKind.Trim(),
            focusLabel.Trim(),
            string.IsNullOrWhiteSpace(address) ? null : address.Trim());

        var path = FocusPath(project, repoRoot);
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        File.WriteAllText(path, JsonSerializer.Serialize(focus, JsonOptions));
        return focus;
    }

    public static BrainFocusDto? TryLoadFocus(string project, string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(project))
            return null;

        var path = FocusPath(project, repoRoot);
        if (!File.Exists(path))
            return null;

        try
        {
            return JsonSerializer.Deserialize<BrainFocusDto>(File.ReadAllText(path), JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    public static BrainDecisionSnapshotDto? TryLoadSnapshot(string project, string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(project))
            return null;

        var memory = BrainMemoryDecay.TryLoad(project, repoRoot);
        var memoryConfidence = memory?.MemoryConfidence ?? 1.0;
        var memoryMessage = memory?.DecayMessage;

        var live = BrainDecisionStore.GetLive(project);
        if (live is not null)
        {
            return BrainDecisionSnapshotDto.FromDecision(
                live,
                project,
                memoryConfidence: memoryConfidence,
                memoryMessage: memoryMessage);
        }

        var path = LastDecisionPath(project, repoRoot);
        if (!File.Exists(path))
            return null;

        try
        {
            var snap = JsonSerializer.Deserialize<BrainDecisionSnapshotDto>(File.ReadAllText(path), JsonOptions);
            if (snap?.LastDecision is not null && snap.Decision is null)
                return BrainDecisionSnapshotDto.FromDecision(
                    snap.LastDecision,
                    snap.Project,
                    snap.Enabled,
                    snap.EmptyHint,
                    memoryConfidence,
                    memoryMessage);
            if (snap is null)
                return null;
            if (snap.MemoryConfidence >= 0.999 && memoryConfidence < 0.999)
                return snap with { MemoryConfidence = memoryConfidence, MemoryMessage = memoryMessage };
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

        var policyLine = decision.HuntPolicy is not null
            ? $" | {HuntPolicyEngine.FormatVerbose(decision.HuntPolicy)}"
            : "";

        return
            $"Brain: {decision.FocusKind} {decision.FocusLabel} [{decision.FocusScore}] " +
            $"mutator={(decision.PreferredMutator ?? "credit")} " +
            $"corpus={decision.CorpusPriorityBias:P0} energy+{decision.RecommendedEnergyBoost} — {terms}{policyLine}";
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
                var score = f.Score + frontierBoost + GravityBoostForAddress(signals.Gravity, f.ToAddress);
                list.Add(new HuntCandidate(
                    "frontier",
                    LabelFrontier(f),
                    score,
                    f.Detail,
                    BuildFrontierTerms(f, frontierBoost, signals.Gravity)));
            }
        }

        if (signals.Gravity?.Wells is { Count: > 0 } wells)
        {
            foreach (var w in wells.Where(w => w.GravityScore >= 35).Take(2))
            {
                var label = w.SinkSymbol ?? w.FunctionName ?? w.Address ?? w.Kind;
                list.Add(new HuntCandidate(
                    "gravity",
                    label,
                    w.GravityScore,
                    w.Detail,
                    BuildGravityTerms(w)));
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
                    $"priority {fn.FuzzPriority}/100 ┬╖ {fn.UncoveredBlockCount} uncovered BB(s)",
                    BuildStaticTerms(fn, signals.Analysis)));
            }

            foreach (var fn in signals.StaticHints.TopChangedFunctions.Take(2))
            {
                list.Add(new HuntCandidate(
                    "patch",
                    fn.Name,
                    ScoreChangedFunction(fn),
                    $"{fn.ChangeKind} ┬╖ priority ╬ö{fn.FuzzPriorityDelta:+0;-0}",
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
                $"{finding.RuleClass} ┬╖ {finding.Severity}",
                BuildOracleTerms(finding, score)));
        }

        foreach (var scream in signals.ScreamClusters
                     .Where(s => !s.Saturated && (s.ScreamScore >= 40 || s.MomentumScore >= 40))
                     .OrderByDescending(s => s.MomentumScore)
                     .ThenByDescending(s => s.ScreamScore)
                     .Take(3))
        {
            var score = Math.Max(scream.ScreamScore, scream.MomentumScore);
            list.Add(new HuntCandidate(
                "scream",
                scream.Function ?? scream.FamilyId ?? scream.ClusterKey,
                score,
                $"novelty {scream.Novelty}/100 · seen×{scream.SeenCount}" +
                (scream.MomentumScore >= 40 ? $" · {scream.MomentumLabel} momentum={scream.MomentumScore}" : "") +
                (scream.Generation > 1 ? $" · gen {scream.Generation}" : ""),
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
        IReadOnlyList<IMutator> mutators,
        IReadOnlyList<MutatorChainRowDto>? chainRows = null,
        HuntPolicyDecision? huntPolicy = null)
    {
        if (top.Kind == "mutator")
            return ResolveMutatorName(mutators, top.Label);

        var creditLead = mutatorRows.FirstOrDefault();
        if (creditLead is not null && chainRows is { Count: > 0 })
        {
            var chainHint = chainRows
                .Where(c => c.Chain.Count >= 2
                            && c.Chain[0].Equals(creditLead.Name, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(c => c.Score)
                .FirstOrDefault();
            if (chainHint is not null)
            {
                var chainNext = ResolveMutatorName(mutators, chainHint.Chain[^1]);
                if (chainNext is not null && creditLead.SelectionWeight >= 3)
                    return chainNext;
            }
        }

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

        if (top.Kind == "scream" && signals.ScreamClusters.Any(s => s.MomentumScore >= 55))
            boost += 2;

        return Math.Clamp(boost, 0, 8);
    }

    private static string BuildSignalsSummary(
        FrontierReportDto? frontier,
        TargetGravityReportDto? gravity,
        GhidraAnalysisOracleHints.HintPack? hints,
        int oracleCount,
        IReadOnlyList<ScreamClusterSignal> screams,
        bool hasData)
    {
        if (!hasData)
            return "no stalk/scream signals ΓÇö brain will no-op";

        var parts = new List<string>();
        if (frontier?.FrontierCount > 0)
            parts.Add($"{frontier.FrontierCount} Scare Door(s)");
        if (gravity?.WellCount > 0)
            parts.Add($"gravity {gravity.AggregatePressure}/100");
        if (hints is not null)
            parts.Add("static map");
        if (oracleCount > 0)
            parts.Add($"{oracleCount} oracle hint(s)");
        var hot = screams.Count(s => !s.Saturated && s.ScreamScore >= 40);
        var warming = screams.Count(s => s.MomentumScore >= 40);
        if (hot > 0)
            parts.Add($"{hot} hot scream(s)");
        if (warming > 0)
            parts.Add($"{warming} warming familie(s)");
        return string.Join(" · ", parts);
    }

    private static IReadOnlyList<ScreamClusterSignal> LoadScreamSignals(string project, string repoRoot)
    {
        var crashes = CrashCatalog.ListAll(repoRoot)
            .Where(c => c.Project.Equals(project, StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (crashes.Count == 0)
            return [];

        var crashesDir = Path.Combine(repoRoot, "data", "crashes", project);
        var familyIndex = ScreamFamilyIndex.TryLoad(project, repoRoot);
        var evolutions = new Dictionary<Guid, ScreamEvolutionDto>();
        if (Directory.Exists(crashesDir))
        {
            foreach (var c in crashes)
            {
                var evo = ScreamEvolutionBuilder.TryRead(
                    ScreamEvolutionBuilder.PathFor(crashesDir, c.Id));
                if (evo is not null)
                    evolutions[c.Id] = evo;
            }
        }

        var byFamily = crashes
            .Select(c =>
            {
                evolutions.TryGetValue(c.Id, out var evo);
                DebuggerObservation? debugger = null;
                if (Directory.Exists(crashesDir))
                {
                    debugger = ScreamInvestigator.TryRead(
                        ScreamInvestigator.ObservationPathFor(crashesDir, c.Id));
                }
                return new { Crash = c, Evolution = evo, Debugger = debugger };
            })
            .GroupBy(x => x.Evolution?.FamilyId ?? x.Crash.ClusterKey ?? x.Crash.Id.ToString(),
                StringComparer.OrdinalIgnoreCase);

        return byFamily
            .Select(g =>
            {
                var lead = g.OrderByDescending(x => x.Evolution?.MomentumScore ?? 0)
                    .ThenByDescending(x => x.Crash.ScreamScore)
                    .First();
                var familyId = lead.Evolution?.FamilyId;
                var indexEntry = familyId is not null
                    ? familyIndex?.Families.FirstOrDefault(f =>
                        f.FamilyId.Equals(familyId, StringComparison.OrdinalIgnoreCase))
                    : null;
                var momentumScore = indexEntry?.EffectiveMomentumScore
                                    ?? lead.Evolution?.MomentumScore
                                    ?? 0;
                var momentumLabel = indexEntry?.MomentumLabel ?? lead.Evolution?.MomentumLabel;
                var seen = g.Count();
                var novelty = lead.Crash.Novelty > 0 ? lead.Crash.Novelty : Math.Max(0, 100 - seen * 8);
                var screamScore = lead.Crash.ScreamScore;
                var saturated = seen >= 8 && novelty < 35 && momentumScore < 40
                                || momentumLabel is "stagnant";
                var progression = lead.Evolution?.ProgressionStep ?? ScreamProgressionStep.Unknown;
                var debuggerBonus = 0;
                string? exploitHint = null;
                if (lead.Debugger?.ExploitabilityHint is { } exp)
                {
                    exploitHint = exp;
                    debuggerBonus = exp.Equals("HIGH", StringComparison.OrdinalIgnoreCase) ? 12
                        : exp.Equals("MEDIUM", StringComparison.OrdinalIgnoreCase) ? 6 : 0;
                }
                else if ((lead.Debugger?.Diagnosis?.Length ?? 0) > 0)
                {
                    debuggerBonus = 4;
                }

                return new ScreamClusterSignal(
                    g.Key,
                    screamScore,
                    novelty,
                    seen,
                    lead.Crash.StaticFunctionSummary,
                    saturated,
                    momentumScore,
                    momentumLabel,
                    indexEntry?.MaxGeneration ?? lead.Evolution?.Generation ?? 0,
                    familyId ?? lead.Evolution?.FamilyId,
                    progression,
                    debuggerBonus,
                    exploitHint);
            })
            .OrderByDescending(s => s.MomentumScore)
            .ThenByDescending(s => s.ScreamScore)
            .ToList();
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
            "session-fork" => $"Session fork ΓåÆ {f.ToAddress}",
            "edge-gap" => $"Edge gap ΓåÆ {f.ToAddress}",
            _ => string.IsNullOrWhiteSpace(f.FunctionName)
                ? $"Unopened door ΓåÆ {f.ToAddress}"
                : $"{f.FunctionName} ΓåÆ {f.ToAddress}",
        };

    internal static List<HuntCandidate> ApplyFocusPreference(
        IReadOnlyList<HuntCandidate> candidates,
        BrainFocusDto focus,
        Signals signals)
    {
        var list = candidates.ToList();
        var idx = list.FindIndex(c => MatchesFocus(c.Kind, c.Label, focus));
        if (idx >= 0)
        {
            var match = list[idx];
            var boosted = Math.Max(match.Score, list.Max(c => c.Score) + 8);
            var terms = new List<OracleScoreTerm>(match.Terms)
            {
                new("pinned focus", 12, focus.FocusLabel),
            };
            list.RemoveAt(idx);
            list.Insert(0, match with { Score = boosted, Terms = terms });
            return list;
        }

        if (signals.Frontier?.Frontiers is { Count: > 0 } frontiers
            && focus.FocusKind.Equals("frontier", StringComparison.OrdinalIgnoreCase))
        {
            var frontier = frontiers.FirstOrDefault(f =>
                (!string.IsNullOrWhiteSpace(focus.Address)
                 && f.ToAddress.Equals(focus.Address, StringComparison.OrdinalIgnoreCase))
                || LabelFrontier(f).Equals(focus.FocusLabel, StringComparison.OrdinalIgnoreCase));

            if (frontier is not null)
            {
                var richnessBoost = FrontierRichnessBoost(signals);
                var score = Math.Max(
                    frontier.Score + richnessBoost + 12,
                    list.Count > 0 ? list.Max(c => c.Score) + 5 : frontier.Score + 12);
                var terms = new List<OracleScoreTerm>(BuildFrontierTerms(frontier, richnessBoost))
                {
                    new("pinned focus", 12, focus.FocusLabel),
                };
                list.Insert(0, new HuntCandidate(
                    "frontier",
                    LabelFrontier(frontier),
                    score,
                    frontier.Detail,
                    terms));
            }
        }

        return list;
    }

    private static bool MatchesFocus(HuntCandidate candidate, BrainFocusDto focus) =>
        MatchesFocus(candidate.Kind, candidate.Label, focus);

    private static bool MatchesFocus(string kind, string label, BrainFocusDto focus) =>
        kind.Equals(focus.FocusKind, StringComparison.OrdinalIgnoreCase)
        && (label.Equals(focus.FocusLabel, StringComparison.OrdinalIgnoreCase)
            || (!string.IsNullOrWhiteSpace(focus.Address)
                && label.Contains(focus.Address, StringComparison.OrdinalIgnoreCase)));

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

    private static int GravityBoostForAddress(TargetGravityReportDto? gravity, string? address)
    {
        if (gravity is null || string.IsNullOrWhiteSpace(address))
            return 0;
        return Math.Min(12, TargetGravityEngine.LookupGravityForAddress(gravity, address) / 8);
    }

    private static IReadOnlyList<OracleScoreTerm> BuildGravityTerms(TargetGravityWellDto w) =>
    [
        new("gravity pressure", w.GravityScore, w.Kind),
        new("sink risk", Math.Min(12, (int)Math.Round(w.Risk / 8)), w.SinkSymbol ?? w.Kind),
        new("reach distance", Math.Max(1, 10 - w.Distance), $"{w.Distance} hop(s)"),
    ];

    private static IReadOnlyList<OracleScoreTerm> BuildFrontierTerms(
        FrontierBranchDto f,
        int richnessBoost = 0,
        TargetGravityReportDto? gravity = null)
    {
        var terms = new List<OracleScoreTerm> { new("frontier rank", f.Score, f.Kind) };
        if (richnessBoost > 0)
            terms.Add(new OracleScoreTerm("frontier richness", richnessBoost,
                $"{f.Score + richnessBoost} boosted"));
        var gBoost = GravityBoostForAddress(gravity, f.ToAddress);
        if (gBoost > 0)
            terms.Add(new OracleScoreTerm("target gravity", gBoost, "sink pull"));
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

    private static IReadOnlyList<OracleScoreTerm> BuildScreamTerms(ScreamClusterSignal scream)
    {
        var terms = new List<OracleScoreTerm>
        {
            new("scream score", Math.Min(40, scream.ScreamScore / 2), $"{scream.ScreamScore}"),
            new("novelty", Math.Min(20, scream.Novelty / 5), $"{scream.Novelty}/100"),
            new("cluster size", scream.SeenCount <= 1 ? 12 : -Math.Min(10, scream.SeenCount), $"seen×{scream.SeenCount}"),
        };
        if (scream.MomentumScore >= 40)
            terms.Add(new OracleScoreTerm("evolution momentum", Math.Min(20, scream.MomentumScore / 4),
                $"{scream.MomentumLabel} {scream.MomentumScore}"));
        if (scream.Generation > 1)
            terms.Add(new OracleScoreTerm("lineage generation", Math.Min(8, scream.Generation), $"gen {scream.Generation}"));
        return terms;
    }

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
