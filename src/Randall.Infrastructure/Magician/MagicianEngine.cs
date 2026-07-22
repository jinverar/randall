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

    /// <summary>Manual / CLI cast for an explicit need (knight, army, bots, …).</summary>
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
        sb.AppendLine();
        sb.AppendLine("Oracle need → spell map: dictionary→dictionaryBoost; energy→energyBless;");
        sb.AppendLine("hunter→summonHunter; knight→summonKnight; army→summonArmy; bots→summonBots; rearm→rearmOracles.");
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
            case "rearm":
                yield return "rearmOracles";
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
            default:
                return (false, null, $"unknown spell {spellId}");
        }
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
