using System.Text;
using Randall.Contracts;
using Randall.Core;
using Randall.Infrastructure.BugHunt;
using Randall.Infrastructure.Mutators;
using Randall.Infrastructure.Oracles;

namespace Randall.Infrastructure.Magician;

/// <summary>
/// Magician engine — intervention / summoning.
/// Receives <see cref="OracleNeedDto"/> foresight from the Oracle, casts spells on the
/// campaign (dictionary, mutators, energy), and can summon Bug Hunter, a coverage knight,
/// a mutator army, or analyst bots (AI-seed hints). Does not judge runs.
/// </summary>
public static class MagicianEngine
{
    public static readonly string[] Catalog =
    [
        "dictionaryBoost",
        "havocSurge",
        "energyBless",
        "rearmOracles",
        "summonHunter",
        "summonKnight",
        "summonArmy",
        "summonBots",
        "summonJoker",
        "playJokerCard",
        "capitalizeJoker",
        "rewindScream",
        "evolutionBless",
        "hypothesisExperiment",
    ];

    public static bool IsEnabled(ProjectConfig project) =>
        project.Magician is { Enabled: true };

    public static MagicianConfig GetConfig(ProjectConfig project) =>
        project.Magician ?? new MagicianConfig { Enabled = false };

    /// <summary>Campaign-start blessing (optional army + hunter arming).</summary>
    public static MagicianCastResult? PrepareForFuzz(
        ProjectConfig project,
        string yamlPath,
        IFuzzProgressSink? progress)
    {
        var cfg = GetConfig(project);
        if (cfg is not { Enabled: true, BlessOnStart: true })
            return null;

        project.Magician ??= cfg;
        var needs = new List<OracleNeedDto>
        {
            new("army", "Magician opening blessing — mutator army ready", null, null, "nearMiss"),
            new("hunter", "Magician opening blessing — Bug Hunter on call for AI/robot code", null, null, "nearMiss"),
        };
        if (project.Joker is { Enabled: true } || cfg.AllowSummonJoker)
            needs.Add(new("joker", "Magician invites the Joker for chaotic tricks", null, null, "nearMiss"));
        var cast = Cast(project, yamlPath, needs, iteration: 0, corpus: null, payload: null,
            mutators: null, progress: progress, force: true);
        if (!string.IsNullOrEmpty(cast.Summary))
            FuzzAnalystLog.Info(progress, $"Magician bless: {cast.Summary}");
        return cast;
    }

    /// <summary>React to an Oracle evaluation (findings → needs → spells).</summary>
    public static MagicianCastResult? OnOracleEval(
        ProjectConfig project,
        string yamlPath,
        OracleEvalResult eval,
        CorpusTracker? corpus,
        byte[]? payload,
        List<IMutator>? mutators,
        IFuzzProgressSink? progress)
    {
        var cfg = GetConfig(project);
        if (cfg is not { Enabled: true, AutoCastOnOracle: true })
            return null;
        if (eval.Needs.Count == 0 && eval.Findings.Count == 0)
            return null;

        var needs = eval.Needs.Count > 0
            ? eval.Needs
            : OracleNeeds.FromFindings(eval.Findings);

        var cast = Cast(project, yamlPath, needs, iteration: eval.Findings.FirstOrDefault()?.Iteration ?? 0,
            corpus, payload, mutators, progress, force: false);

        if (!string.IsNullOrEmpty(cast.Summary))
        {
            FuzzAnalystLog.Info(progress,
                $"Magician [{cast.Spells.Count} spell(s)]: {cast.Summary}",
                eval.Findings.FirstOrDefault()?.Iteration ?? 0);
        }

        return cast;
    }

    /// <summary>Magician watches a Joker trick (log / persist) — does not change judgment.</summary>
    public static void WatchJoker(
        ProjectConfig project,
        string yamlPath,
        JokerTrick trick,
        int iteration,
        bool crashed,
        bool capitalized,
        IFuzzProgressSink? progress)
    {
        var cfg = GetConfig(project);
        if (cfg is not { Enabled: true, WatchJoker: true } && !JokerEngine.IsEnabled(project))
            return;

        var act = new JokerActDto(
            trick.Id, project.Name, trick.TrickName, trick.MutatorChain.ToList(),
            trick.ChaosLevel, trick.Detail, iteration, crashed, capitalized, DateTimeOffset.UtcNow);

        if (cfg.PersistSpells || cfg.WatchJoker)
        {
            var dir = Path.Combine(
                ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CrashesDir),
                "_magician");
            JokerEngine.PersistWatch(dir, act);
        }

        if (crashed)
            FuzzAnalystLog.Warn(progress,
                $"Magician watched Joker [{trick.TrickName}] CRASH — {trick.Detail}", iteration);
        else if (iteration % 25 == 0 || trick.ChaosLevel >= 3)
            FuzzAnalystLog.Info(progress,
                $"Magician watched Joker [{trick.TrickName}] — {string.Join('→', trick.MutatorChain.Take(5))}",
                iteration);
    }

    /// <summary>
    /// After the Joker's random funny tricks find a crash, Magician capitalizes:
    /// corpus retain/energy, mutator army, dictionary pressure, punchline note.
    /// </summary>
    public static MagicianCastResult? CapitalizeOnJokerCrash(
        ProjectConfig project,
        string yamlPath,
        JokerTrick trick,
        byte[] payload,
        CorpusTracker corpus,
        List<IMutator>? mutators,
        int iteration,
        IFuzzProgressSink? progress)
    {
        var cfg = GetConfig(project);
        if (cfg is not { Enabled: true, CapitalizeJokerCrashes: true })
        {
            WatchJoker(project, yamlPath, trick, iteration, crashed: true, capitalized: false, progress);
            return null;
        }

        project.Magician ??= cfg;
        project.Magician.Enabled = true;

        if (corpus.IsNew(payload))
            corpus.SaveInteresting(payload, "joker");
        corpus.BoostEnergy(payload, 12);

        var needs = new List<OracleNeedDto>
        {
            new("army", $"Joker {trick.TrickName} crashed — muster army on the punchline", "joker", trick.TrickName, "violation"),
            new("dictionary", $"Joker crash — dictionary pressure from chaos path", "joker", trick.TrickName, "violation"),
            new("energy", $"Joker crash energy bless", "joker", trick.TrickName, "violation"),
        };

        var cast = Cast(project, yamlPath, needs, iteration, corpus, payload, mutators, progress, force: true);

        // Explicit capitalize spell record
        var spell = new MagicianSpellDto(
            Guid.NewGuid().ToString("N")[..12],
            project.Name,
            "capitalizeJoker",
            "joker",
            $"Capitalize on Joker {trick.TrickName} crash",
            "joker",
            trick.TrickName,
            iteration,
            $"chain={string.Join('→', trick.MutatorChain)} +12 energy",
            DateTimeOffset.UtcNow);
        if (cfg.PersistSpells)
        {
            var dir = Path.Combine(
                ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CrashesDir),
                "_magician");
            new MagicianSpellStore(dir).Append(spell);
            WriteJokerPunchline(dir, project, trick, cast);
        }

        WatchJoker(project, yamlPath, trick, iteration, crashed: true, capitalized: true, progress);
        FuzzAnalystLog.Warn(progress,
            $"Magician capitalized on Joker [{trick.TrickName}]: {cast.Summary}", iteration);

        return cast with
        {
            Spells = cast.Spells.Concat([spell]).ToList(),
            Summary = string.IsNullOrEmpty(cast.Summary)
                ? "capitalizeJoker→joker"
                : $"capitalizeJoker→joker; {cast.Summary}",
            ExtraEnergyBoost = cast.ExtraEnergyBoost + 12,
        };
    }

    /// <summary>
    /// Stub hook when <see cref="FuzzConfig.RewindScream"/> is on — logs TTD record/replay hint (no capture).
    /// See docs/RECORDING.md#windbg-ttd-rewind-scream-stub.
    /// </summary>
    public static MagicianCastResult? RewindScreamOnCrash(
        ProjectConfig project,
        string yamlPath,
        Guid crashId,
        string? dumpPath,
        DeepScreamDto? deepScream,
        IFuzzProgressSink? progress)
    {
        if (!project.Fuzz.RewindScream)
            return null;
        if (deepScream is not { Ok: true, IsCandidate: true })
            return null;

        var cfg = GetConfig(project);
        if (cfg is not { Enabled: true, AllowRewindScream: true })
            return null;

        project.Magician ??= cfg;
        var crashesDir = Path.Combine(
            ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CrashesDir));
        var ttdPath = DeepScreamBuilder.WriteTtdOperatorHint(
            crashesDir, crashId, project.Name, deepScream, dumpPath);
        DeepScreamBuilder.WithTtdHint(crashesDir, deepScream, ttdPath);

        var dir = Path.Combine(crashesDir, "_magician");
        Directory.CreateDirectory(dir);
        var indexPath = Path.Combine(dir, "rewind_scream_hint.md");
        var indexLine = $"- `{crashId:N}` scream={deepScream.ScreamScore} → `{ttdPath}`{Environment.NewLine}";
        if (File.Exists(indexPath))
            File.AppendAllText(indexPath, indexLine);
        else
        {
            var header = new StringBuilder();
            header.AppendLine("# Deep Scream — TTD operator index (Phase D)");
            header.AppendLine();
            header.AppendLine("Randfuzz does **not** capture TTD traces. Crashes below passed the Deep Scream gate:");
            header.AppendLine();
            header.Append(indexLine);
            File.WriteAllText(indexPath, header.ToString());
        }

        var spell = new MagicianSpellDto(
            Guid.NewGuid().ToString("N")[..12],
            project.Name,
            "rewindScream",
            "ttd",
            $"Deep Scream TTD operator hint — scream={deepScream.ScreamScore}",
            null,
            null,
            0,
            ttdPath,
            DateTimeOffset.UtcNow);
        if (cfg.PersistSpells)
            new MagicianSpellStore(dir).Append(spell);

        FuzzAnalystLog.Info(progress,
            $"[deep-scream] TTD operator hint → {ttdPath} (external capture — see docs/RECORDING.md)", 0);

        return new MagicianCastResult([spell], [], [], 0, false, false, "deepScream→ttd");
    }

    /// <summary>
    /// When scream evolution momentum is high, bless the warming lineage: corpus energy,
    /// mutator army / havoc, and optional dictionary pressure on the family mutators.
    /// </summary>
    public static MagicianCastResult? OnScreamEvolutionWarm(
        ProjectConfig project,
        string yamlPath,
        ScreamEvolutionDto evolution,
        CrashSidecarDto? sidecar,
        CorpusTracker? corpus,
        List<IMutator>? mutators,
        int iteration,
        IFuzzProgressSink? progress)
    {
        if (evolution is not { Ok: true, MomentumScore: >= 40 })
            return null;

        var cfg = GetConfig(project);
        if (cfg is not { Enabled: true })
            return null;

        project.Magician ??= cfg;
        var lineage = sidecar?.MutatorChain?.ToList()
                      ?? (sidecar?.Mutator is { } m ? new List<string> { m } : []);

        var reason =
            $"Scream evolution {evolution.MomentumLabel} (momentum={evolution.MomentumScore}, gen={evolution.Generation}) — {evolution.Summary}";
        var needs = new List<OracleNeedDto>
        {
            new("evolution", reason, "scream", evolution.FamilyId, "violation"),
            new("energy", $"Warm lineage energy — {evolution.ProgressionStep}", "scream", evolution.FamilyId, "violation"),
        };

        if (lineage.Count >= 2)
            needs.Add(new("army", $"Breed mutator chain on warming scream family", "scream", evolution.FamilyId, "violation"));

        var cast = Cast(project, yamlPath, needs, iteration, corpus, null, mutators, progress, force: true);

        if (!string.IsNullOrEmpty(cast.Summary))
            FuzzAnalystLog.Info(progress, $"Magician evolution: {cast.Summary}", iteration);

        return cast;
    }

    /// <summary>Phase C — Hunt Policy flagged experiment; queue hypothesis and bless budget.</summary>
    public static void OnHuntPolicyNeedsExperiment(
        ProjectConfig project,
        string yamlPath,
        HuntPolicyDecision policy,
        int iteration,
        IFuzzProgressSink? progress)
    {
        if (policy is not { NeedsExperiment: true })
            return;

        HypothesisDto? hypothesis = null;
        if (!string.IsNullOrWhiteSpace(policy.TopHypothesisId))
        {
            hypothesis = HypothesisEngine.FindTopForProject(project.Name);
            if (hypothesis is not null
                && !hypothesis.Id.Equals(policy.TopHypothesisId, StringComparison.OrdinalIgnoreCase))
                hypothesis = null;
        }

        hypothesis ??= HypothesisEngine.FindTopForProject(project.Name);

        if (hypothesis is { ConfidencePercent: >= HypothesisEngine.MinExperimentConfidence })
        {
            HypothesisEngine.EnqueueFromHypothesis(project.Name, hypothesis, iteration);
            var cfg = GetConfig(project);
            if (cfg is { Enabled: true })
            {
                project.Magician ??= cfg;
                if (hypothesis.ConfidencePercent >= HypothesisEngine.MagicianBudgetConfidence)
                {
                    var cast = OnHypothesisQueued(
                        project, yamlPath, hypothesis, policy, iteration, progress);
                    if (!string.IsNullOrEmpty(cast?.Summary))
                        FuzzAnalystLog.Info(progress, $"Magician hypothesis: {cast.Summary}", iteration);
                }
            }

            FuzzAnalystLog.Info(progress,
                HypothesisEngine.FormatVerbose(hypothesis), iteration);
            return;
        }

        var cfg2 = GetConfig(project);
        if (cfg2 is not { Enabled: true, PersistSpells: true })
        {
            FuzzAnalystLog.Info(progress,
                $"Hunt policy needs-experiment: {policy.ExperimentHint}", iteration);
            return;
        }

        var dir = Path.Combine(
            ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CrashesDir),
            "_magician");
        HypothesisEngine.AppendMagicianHint(dir, new HypothesisDto(
            "hyp-stub", null, policy.ExperimentHint ?? "needs experiment", 0,
            new HypothesisExperimentDto(HypothesisExperimentKind.ReplayLineage, "await crash hypotheses"),
            "Phase C hypothesis or Phase D TTD", HypothesisStatus.Pending),
            iteration, policy.ExperimentHint);

        FuzzAnalystLog.Info(progress,
            $"Hunt policy needs-experiment → {dir}: {policy.ExperimentHint}", iteration);
    }

    /// <summary>Magician blesses a high-confidence hypothesis with small execution budget.</summary>
    public static MagicianCastResult? OnHypothesisQueued(
        ProjectConfig project,
        string yamlPath,
        HypothesisDto hypothesis,
        HuntPolicyDecision policy,
        int iteration,
        IFuzzProgressSink? progress)
    {
        var cfg = GetConfig(project);
        if (cfg is not { Enabled: true })
            return null;

        project.Magician ??= cfg;
        var needs = new List<OracleNeedDto>
        {
            new("hypothesis", hypothesis.Statement, "hypothesis", hypothesis.Id, "nearMiss"),
            new("energy", $"Hypothesis budget — {hypothesis.Experiment.Kind}", "hypothesis", hypothesis.Id, "nearMiss"),
        };

        var cast = Cast(project, yamlPath, needs, iteration, corpus: null, payload: null,
            mutators: null, progress, force: true);

        var dir = Path.Combine(
            ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CrashesDir),
            "_magician");
        var hintPath = HypothesisEngine.AppendMagicianHint(dir, hypothesis, iteration, policy.ExperimentHint);

        var spell = new MagicianSpellDto(
            Guid.NewGuid().ToString("N")[..12],
            project.Name,
            "hypothesisExperiment",
            "hypothesis",
            hypothesis.Statement,
            "hypothesis",
            hypothesis.Id,
            iteration,
            $"{hypothesis.Experiment.Kind} conf={hypothesis.ConfidencePercent}% → {hintPath}",
            DateTimeOffset.UtcNow);
        if (cfg.PersistSpells)
            new MagicianSpellStore(dir).Append(spell);

        return cast with
        {
            Spells = cast.Spells.Concat([spell]).ToList(),
            Summary = string.IsNullOrEmpty(cast.Summary)
                ? "hypothesisExperiment→hypothesis"
                : $"hypothesisExperiment→hypothesis; {cast.Summary}",
        };
    }

    /// <summary>Manual / CLI cast for an explicit need (knight, army, bots, joker, …).</summary>
    public static MagicianCastResult CastNeed(
        ProjectConfig project,
        string yamlPath,
        string request,
        string? reason = null,
        List<IMutator>? mutators = null,
        IFuzzProgressSink? progress = null)
    {
        project.Magician ??= new MagicianConfig { Enabled = true };
        project.Magician.Enabled = true;
        var need = new OracleNeedDto(
            request.Trim().ToLowerInvariant(),
            reason ?? $"Manual Magician cast: {request}",
            null, null, "nearMiss");
        return Cast(project, yamlPath, [need], 0, null, null, mutators, progress, force: true);
    }

    public static MagicianCastResult Cast(
        ProjectConfig project,
        string yamlPath,
        IReadOnlyList<OracleNeedDto> needs,
        int iteration,
        CorpusTracker? corpus,
        byte[]? payload,
        List<IMutator>? mutators,
        IFuzzProgressSink? progress,
        bool force)
    {
        var cfg = GetConfig(project);
        if (!cfg.Enabled && !force)
            return Empty();

        if (force)
        {
            project.Magician ??= new MagicianConfig { Enabled = true };
            project.Magician.Enabled = true;
            cfg = project.Magician;
        }

        var spells = new List<MagicianSpellDto>();
        var mutatorsEnsured = new List<string>();
        var tokensAdded = new List<string>();
        var extraEnergy = 0;
        var coverageOn = false;
        var hunterRearmed = false;
        var castIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var need in needs)
        {
            if (spells.Count >= Math.Max(1, cfg.MaxSpellsPerEval))
                break;

            foreach (var spellId in MapNeedToSpells(need.Request, cfg))
            {
                if (spells.Count >= Math.Max(1, cfg.MaxSpellsPerEval))
                    break;
                if (!IsAllowed(cfg, spellId))
                    continue;
                if (!castIds.Add(spellId))
                    continue;

                var (ok, summon, detail) = ExecuteSpell(
                    spellId, project, yamlPath, need, corpus, payload, mutators,
                    ref extraEnergy, ref coverageOn, ref hunterRearmed,
                    mutatorsEnsured, tokensAdded);

                if (!ok)
                    continue;

                var spell = new MagicianSpellDto(
                    Guid.NewGuid().ToString("N")[..12],
                    project.Name,
                    spellId,
                    summon,
                    need.Reason,
                    need.RuleClass,
                    need.RuleId,
                    iteration,
                    detail,
                    DateTimeOffset.UtcNow);
                spells.Add(spell);
            }
        }

        if (cfg.PersistSpells && spells.Count > 0)
            Persist(project, yamlPath, spells);

        var summary = spells.Count == 0
            ? ""
            : string.Join("; ", spells.Select(s =>
                s.Summon is null ? s.Spell : $"{s.Spell}→{s.Summon}"));

        return new MagicianCastResult(
            spells, mutatorsEnsured, tokensAdded, extraEnergy, coverageOn, hunterRearmed, summary);
    }

    public static string DescribeCatalog()
    {
        var sb = new StringBuilder();
        sb.AppendLine("Magician spell catalog (docs/MAGICIAN.md)");
        sb.AppendLine();
        sb.AppendLine("| Spell | Summon | Effect |");
        sb.AppendLine("|-------|--------|--------|");
        sb.AppendLine("| dictionaryBoost | — | Inject framing / AI-mistake tokens into the campaign dictionary |");
        sb.AppendLine("| havocSurge | — | Ensure havoc mutator is live |");
        sb.AppendLine("| energyBless | — | Extra corpus energy on the offending input |");
        sb.AppendLine("| rearmOracles | — | Merge Bug Hunter oracle rule pack |");
        sb.AppendLine("| summonHunter | hunter | Re-arm Bug Hunter (AI/robot mistake focus) |");
        sb.AppendLine("| summonKnight | knight | Enable coverage-guided stalking |");
        sb.AppendLine("| summonArmy | army | Broad mutator set (havoc, interesting, dict, splice, …) |");
        sb.AppendLine("| summonBots | bots | Write analyst hint for AI seed / hunt (no live API) |");
        sb.AppendLine("| summonJoker | joker | Call the Joker — boost chaotic random tricks (encore) |");
        sb.AppendLine("| capitalizeJoker | joker | (auto) After Joker crash — energy + army + corpus |");
        sb.AppendLine("| playJokerCard | joker | Queue a legendary Joker Card draw from the deck |");
        sb.AppendLine("| rewindScream | ttd | (stub) Write TTD record/replay hint on crash — no capture |");
        sb.AppendLine("| evolutionBless | — | (auto) High scream momentum — energy + army on warming lineage |");
        sb.AppendLine("| hypothesisExperiment | hypothesis | (auto) Phase C hypothesis queue — sweep/hold budget |");
        sb.AppendLine();
        sb.AppendLine("Oracle need → spell map: dictionary→dictionaryBoost; energy→energyBless;");
        sb.AppendLine("hunter→summonHunter; knight→summonKnight; army→summonArmy; bots→summonBots;");
        sb.AppendLine("rearm→rearmOracles; joker→summonJoker; evolution→evolutionBless+energyBless.");
        return sb.ToString();
    }

    private static MagicianCastResult Empty() =>
        new([], [], [], 0, false, false, "");

    private static bool IsAllowed(MagicianConfig cfg, string spellId) =>
        cfg.AllowedSpells.Count == 0 ||
        cfg.AllowedSpells.Any(s => s.Equals(spellId, StringComparison.OrdinalIgnoreCase));

    private static IEnumerable<string> MapNeedToSpells(string request, MagicianConfig cfg)
    {
        switch (request.Trim().ToLowerInvariant())
        {
            case "dictionary":
                yield return "dictionaryBoost";
                yield return "havocSurge";
                break;
            case "energy":
                yield return "energyBless";
                break;
            case "hunter":
                if (cfg.AllowSummonHunter)
                    yield return "summonHunter";
                yield return "rearmOracles";
                break;
            case "knight":
                if (cfg.AllowSummonKnight)
                    yield return "summonKnight";
                break;
            case "army":
                if (cfg.AllowSummonArmy)
                    yield return "summonArmy";
                yield return "havocSurge";
                break;
            case "bots":
                if (cfg.AllowSummonBots)
                    yield return "summonBots";
                break;
            case "joker":
                if (cfg.AllowSummonJoker)
                    yield return "summonJoker";
                if (cfg.AllowPlayJokerCard && Random.Shared.NextDouble() < 0.12)
                    yield return "playJokerCard";
                break;
            case "rearm":
                yield return "rearmOracles";
                break;
            case "evolution":
                yield return "evolutionBless";
                yield return "energyBless";
                if (cfg.AllowSummonArmy)
                    yield return "summonArmy";
                yield return "havocSurge";
                break;
            case "hypothesis":
                yield return "hypothesisExperiment";
                yield return "energyBless";
                if (cfg.AllowSummonArmy)
                    yield return "summonArmy";
                break;
            default:
                // Treat unknown request as a direct spell id if it matches the catalog.
                if (Catalog.Contains(request, StringComparer.OrdinalIgnoreCase))
                    yield return request;
                break;
        }
    }

    private static (bool Ok, string? Summon, string Detail) ExecuteSpell(
        string spellId,
        ProjectConfig project,
        string yamlPath,
        OracleNeedDto need,
        CorpusTracker? corpus,
        byte[]? payload,
        List<IMutator>? mutators,
        ref int extraEnergy,
        ref bool coverageOn,
        ref bool hunterRearmed,
        List<string> mutatorsEnsured,
        List<string> tokensAdded)
    {
        switch (spellId)
        {
            case "dictionaryBoost":
            {
                var added = 0;
                foreach (var tok in TokensFor(need.RuleClass))
                {
                    if (project.Dictionary.Contains(tok, StringComparer.Ordinal))
                        continue;
                    project.Dictionary.Add(tok);
                    tokensAdded.Add(tok);
                    added++;
                }

                EnsureMutator(project, mutators, yamlPath, corpus, "dictionary", mutatorsEnsured);
                RefreshDictionaryMutator(project, yamlPath, corpus, mutators);
                return (true, null, added == 0
                    ? "dictionary already armed"
                    : $"added {added} token(s)");
            }
            case "havocSurge":
                EnsureMutator(project, mutators, yamlPath, corpus, "havoc", mutatorsEnsured);
                return (true, null, "havoc live");
            case "energyBless":
                if (corpus is not null && payload is { Length: > 0 })
                {
                    corpus.BoostEnergy(payload, 5);
                    extraEnergy += 5;
                    return (true, null, "+5 corpus energy");
                }
                return (true, null, "no payload to bless (logged only)");
            case "rearmOracles":
                project.Oracles = BugHunterOracleSuggestions.MergeInto(project.Oracles);
                return (true, null, "oracle pack re-armed from Bug Hunter suggestions");
            case "summonHunter":
                if (!GetConfig(project).AllowSummonHunter)
                    return (false, null, "summonHunter disabled");
                project.BugHunter ??= new BugHunterConfig();
                project.BugHunter.Enabled = true;
                project.BugHunter.AutoArmOracles = true;
                project.BugHunter.AutoArmDictionary = true;
                _ = BugHunterEngine.PrepareForFuzz(project, yamlPath, progress: null);
                hunterRearmed = true;
                return (true, "hunter", "Bug Hunter summoned — AI/robot mistake arming");
            case "summonKnight":
                if (!GetConfig(project).AllowSummonKnight)
                    return (false, null, "summonKnight disabled");
                if (!project.Fuzz.CoverageGuided)
                {
                    project.Fuzz.CoverageGuided = true;
                    coverageOn = true;
                    return (true, "knight", "coverageGuided enabled — knight stalks new paths");
                }
                return (true, "knight", "knight already on duty (coverageGuided)");
            case "summonArmy":
            {
                if (!GetConfig(project).AllowSummonArmy)
                    return (false, null, "summonArmy disabled");
                string[] army = ["havoc", "interesting", "dictionary", "bitflip", "expand", "insert", "arith", "splice"];
                foreach (var m in army)
                    EnsureMutator(project, mutators, yamlPath, corpus, m, mutatorsEnsured);
                return (true, "army", $"army mustered ({string.Join(",", mutatorsEnsured.DefaultIfEmpty("ready"))})");
            }
            case "summonBots":
            {
                if (!GetConfig(project).AllowSummonBots)
                    return (false, null, "summonBots disabled");
                var hint = WriteBotHint(project, yamlPath, need);
                return (true, "bots", $"analyst bots queued — {hint}");
            }
            case "summonJoker":
            {
                if (!GetConfig(project).AllowSummonJoker)
                    return (false, null, "summonJoker disabled");
                project.Joker ??= new JokerConfig();
                project.Joker.Enabled = true;
                project.Joker.EncoreIterations = Math.Max(project.Joker.EncoreIterations, 40);
                project.Joker.Chance = Math.Max(project.Joker.Chance, 0.12);
                return (true, "joker",
                    $"Joker encore {project.Joker.EncoreIterations} iters @ chance≈{project.Joker.EncoreChance:0.00}");
            }
            case "playJokerCard":
            {
                if (!GetConfig(project).AllowPlayJokerCard)
                    return (false, null, "playJokerCard disabled");
                project.Joker ??= new JokerConfig { Enabled = true, DeckEnabled = true };
                project.Joker.Enabled = true;
                project.Joker.DeckEnabled = true;
                JokerEngine.QueueDeckDraw(project, legendary: true);
                return (true, "joker", "Magician queued legendary Joker Card draw");
            }
            case "capitalizeJoker":
                return (true, "joker", "capitalize is automatic on Joker crashes during fuzz");
            case "rewindScream":
                if (!GetConfig(project).AllowRewindScream || !project.Fuzz.RewindScream)
                    return (false, null, "rewindScream disabled — set fuzz.rewindScream: true");
                return (true, "ttd", "rewindScream armed — Deep Scream candidates get TTD operator hints");
            case "evolutionBless":
            {
                var lineage = need.RuleId ?? need.RuleClass ?? "lineage";
                if (corpus is not null && payload is { Length: > 0 })
                {
                    var boost = 8;
                    corpus.BoostEnergy(payload, boost);
                    extraEnergy += boost;
                }
                else
                {
                    extraEnergy += 4;
                }

                EnsureMutator(project, mutators, yamlPath, corpus, "havoc", mutatorsEnsured);
                if (GetConfig(project).AllowSummonArmy)
                    EnsureMutator(project, mutators, yamlPath, corpus, "splice", mutatorsEnsured);
                return (true, null, $"evolution bless on {lineage} (+energy, havoc live)");
            }
            case "hypothesisExperiment":
            {
                var hypId = need.RuleId ?? "hypothesis";
                EnsureMutator(project, mutators, yamlPath, corpus, "bitflip", mutatorsEnsured);
                EnsureMutator(project, mutators, yamlPath, corpus, "interesting", mutatorsEnsured);
                if (GetConfig(project).AllowSummonArmy)
                    EnsureMutator(project, mutators, yamlPath, corpus, "splice", mutatorsEnsured);
                extraEnergy += 3;
                return (true, "hypothesis", $"hypothesis experiment armed — {hypId} (+3 energy budget)");
            }
            default:
                return (false, null, $"unknown spell {spellId}");
        }
    }

    private static void WriteJokerPunchline(
        string magicianDir,
        ProjectConfig project,
        JokerTrick trick,
        MagicianCastResult cast)
    {
        Directory.CreateDirectory(magicianDir);
        var path = Path.Combine(magicianDir, "joker_punchline.md");
        var sb = new StringBuilder();
        sb.AppendLine("# Magician capitalized on a Joker crash");
        sb.AppendLine();
        sb.AppendLine($"Project: `{project.Name}`");
        sb.AppendLine($"Trick: **{trick.TrickName}** (`{trick.Id}`)");
        sb.AppendLine($"Chain: `{string.Join(" → ", trick.MutatorChain)}`");
        sb.AppendLine($"Chaos: {trick.ChaosLevel}");
        sb.AppendLine();
        sb.AppendLine("The Joker threw random funny tricks; Magician kept the scream and stacked pressure.");
        sb.AppendLine();
        sb.AppendLine($"Follow-up spells: {cast.Summary}");
        sb.AppendLine();
        sb.AppendLine("```bash");
        sb.AppendLine($"randall crashes -p {project.Name}");
        sb.AppendLine($"randall magician -p {project.Name}");
        sb.AppendLine("```");
        File.WriteAllText(path, sb.ToString());
    }

    private static IEnumerable<string> TokensFor(string? ruleClass)
    {
        var cls = (ruleClass ?? "").ToLowerInvariant();
        return cls switch
        {
            "auth" or "state" =>
            [
                "admin", "root", "Authorization: Bearer ", "role=admin", "isAdmin=true",
                "BIND_ACK", "RPC_OK", "230 ", "331 ",
            ],
            "integer" or "structure" =>
            [
                "\xff\xff\xff\xff", "\x00\x00\x00\x00", "Content-Length: 999999",
                "Transfer-Encoding: chunked",
            ],
            "resource" => ["AAAA", new string('A', 256), new string('B', 1024)],
            _ => BugHunterMistakes.DefaultDictionaryTokens().Take(12),
        };
    }

    private static void EnsureMutator(
        ProjectConfig project,
        List<IMutator>? mutators,
        string yamlPath,
        CorpusTracker? corpus,
        string name,
        List<string> ensured)
    {
        if (!project.Mutators.Any(m => m.Equals(name, StringComparison.OrdinalIgnoreCase)))
            project.Mutators.Add(name);

        if (mutators is null)
        {
            ensured.Add(name);
            return;
        }

        if (mutators.Any(m => m.Name.Equals(name, StringComparison.OrdinalIgnoreCase) ||
                              (name is "dictionary" or "dict" && m.Name.Equals("dictionary", StringComparison.OrdinalIgnoreCase)) ||
                              (name is "interesting" or "ints" && m.Name.Equals("interesting", StringComparison.OrdinalIgnoreCase))))
        {
            ensured.Add(name);
            return;
        }

        // splice needs corpus pick — skip live add if no corpus
        if (name.Equals("splice", StringComparison.OrdinalIgnoreCase) && corpus is null)
            return;

        var created = BuiltInMutators.Create([name], context: BuildContext(project, yamlPath, corpus));
        foreach (var m in created)
        {
            if (!mutators.Any(x => x.Name.Equals(m.Name, StringComparison.OrdinalIgnoreCase)))
                mutators.Add(m);
        }
        ensured.Add(name);
    }

    private static void RefreshDictionaryMutator(
        ProjectConfig project,
        string yamlPath,
        CorpusTracker? corpus,
        List<IMutator>? mutators)
    {
        if (mutators is null)
            return;
        mutators.RemoveAll(m => m.Name.Equals("dictionary", StringComparison.OrdinalIgnoreCase));
        var created = BuiltInMutators.Create(["dictionary"], context: BuildContext(project, yamlPath, corpus));
        mutators.AddRange(created);
    }

    private static MutationContext BuildContext(
        ProjectConfig project,
        string yamlPath,
        CorpusTracker? corpus)
    {
        var rng = Random.Shared;
        var seeds = new List<byte[]> { Array.Empty<byte>() };
        return new MutationContext
        {
            DictionaryTokens = BuiltInMutators.BuildDictionaryTokens(project, yamlPath),
            HavocDepth = project.Fuzz.HavocDepth,
            PickAlternateSeed = corpus is null
                ? null
                : () => corpus.PickAny(seeds, rng, project.Fuzz.PowerSchedule),
        };
    }

    private static string WriteBotHint(ProjectConfig project, string yamlPath, OracleNeedDto need)
    {
        var dir = Path.Combine(
            ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CrashesDir),
            "_magician");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "bots_hint.md");
        var sb = new StringBuilder();
        sb.AppendLine("# Magician summoned analyst bots");
        sb.AppendLine();
        sb.AppendLine($"Project: `{project.Name}`");
        sb.AppendLine($"Need: **{need.Request}** — {need.Reason}");
        if (!string.IsNullOrEmpty(need.RuleClass))
            sb.AppendLine($"Oracle rule: `{need.RuleClass}/{need.RuleId}` ({need.Severity})");
        sb.AppendLine();
        sb.AppendLine("Suggested analyst actions (run off the hot path):");
        sb.AppendLine();
        sb.AppendLine("```bash");
        sb.AppendLine($"randall hunt -d <sourceDir> -c {Path.GetFileName(yamlPath)} --arm");
        sb.AppendLine($"randall ai seed -c {Path.GetFileName(yamlPath)} --dry-run");
        sb.AppendLine($"randall oracles -p {project.Name}");
        sb.AppendLine("```");
        sb.AppendLine();
        sb.AppendLine("Bots here are *helpers for AI/robot-authored bug hunting* — not autonomous exploiters.");
        File.WriteAllText(path, sb.ToString());
        return path;
    }

    private static void Persist(ProjectConfig project, string yamlPath, IReadOnlyList<MagicianSpellDto> spells)
    {
        var dir = Path.Combine(
            ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CrashesDir),
            "_magician");
        var store = new MagicianSpellStore(dir);
        foreach (var s in spells)
            store.Append(s);
    }
}
