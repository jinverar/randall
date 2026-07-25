using System.Text.Json;
using Randall.Contracts;
using Randall.Infrastructure.Oracles;

namespace Randall.Infrastructure;

/// <summary>
/// Reads stalk artifacts on disk and assembles the Scare Floor intelligence panel payload.
/// Does not re-run Oracle or Ghidra — consumes persisted JSON only.
/// </summary>
public static class StalkIntelligenceBuilder
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public static StalkIntelligenceDto Build(string project, string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(project))
            throw new ArgumentException("project required");

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();

        var frontier = FrontierEngine.TryLoad(project, repoRoot);
        var analysis = GhidraAnalysisBridge.TryLoad(project, repoRoot);
        var hints = GhidraAnalysisOracleHints.TryBuild(project, repoRoot);
        var oracleFindings = LoadRecentOracleFindings(project, repoRoot, 6);
        var (mutators, mutatorBias) = TryLoadLatestMutatorCredits(project, repoRoot);

        var targets = new List<StalkIntelligenceTargetDto>();

        if (frontier?.Frontiers is { Count: > 0 } frontiers)
        {
            foreach (var f in frontiers.Take(5))
            {
                targets.Add(new StalkIntelligenceTargetDto(
                    $"frontier:{f.EdgeKey}",
                    "frontier",
                    LabelForFrontier(f),
                    f.Score,
                    f.Detail,
                    f.ToAddress,
                    f.FunctionName,
                    BuildFrontierScoreBreakdown(f)));
            }
        }

        if (hints is not null)
        {
            foreach (var fn in hints.TopUncoveredTargets.Take(4))
            {
                targets.Add(new StalkIntelligenceTargetDto(
                    $"static:{fn.Address}",
                    "static",
                    fn.Name,
                    fn.FuzzPriority,
                    BuildStaticDetail(fn),
                    fn.Address,
                    fn.Name,
                    BuildStaticScoreBreakdown(fn, analysis)));
            }

            foreach (var fn in hints.TopFunctions
                         .Where(f => hints.TopUncoveredTargets.All(u =>
                             !u.Name.Equals(f.Name, StringComparison.OrdinalIgnoreCase)))
                         .Take(2))
            {
                targets.Add(new StalkIntelligenceTargetDto(
                    $"static-priority:{fn.Address}",
                    "static",
                    fn.Name,
                    fn.FuzzPriority,
                    $"High static priority ({fn.FuzzPriority}/100)" +
                    (fn.HasDangerousCalls ? $" · {string.Join(", ", fn.DangerousCalls.Take(2))}" : ""),
                    fn.Address,
                    fn.Name,
                    BuildStaticScoreBreakdown(fn, analysis)));
            }
        }

        foreach (var finding in oracleFindings)
        {
            targets.Add(new StalkIntelligenceTargetDto(
                $"oracle:{finding.Id}",
                "oracle",
                finding.RuleId,
                ScoreOracleFinding(finding),
                BuildOracleDetail(finding),
                null,
                null,
                BuildOracleScoreBreakdown(finding)));
        }

        targets = targets
            .OrderByDescending(t => t.Score)
            .ThenBy(t => t.Label, StringComparer.OrdinalIgnoreCase)
            .Take(10)
            .ToList();

        var hasData = frontier is not null || hints is not null || oracleFindings.Count > 0 || mutators.Count > 0;
        var summary = BuildSummary(frontier, hints, oracleFindings.Count, targets);
        var emptyHint =
            "No stalk brain yet — export Ghidra → randall-analysis.json, run fuzz with coverage, " +
            "then `randall stalk frontier -p <project>`. Oracle hints appear after semantic fuzz runs.";

        return new StalkIntelligenceDto(
            project,
            hasData,
            summary,
            emptyHint,
            frontier?.Mode,
            frontier?.Summary,
            hints?.Summary,
            hints?.CoverageGapSummary,
            oracleFindings.Count,
            targets,
            mutators.Take(5).ToList(),
            mutatorBias);
    }

    private static string LabelForFrontier(FrontierBranchDto f) =>
        f.Kind switch
        {
            "session-fork" => $"Session fork → {f.ToAddress}",
            "edge-gap" => $"Edge gap → {f.ToAddress}",
            _ => string.IsNullOrWhiteSpace(f.FunctionName)
                ? $"Gray door → {f.ToAddress}"
                : $"{f.FunctionName} → {f.ToAddress}",
        };

    private static string BuildStaticDetail(RandallAnalysisFunctionDto fn)
    {
        var parts = new List<string> { $"priority {fn.FuzzPriority}/100" };
        if (fn.UncoveredBlockCount > 0)
            parts.Add($"{fn.UncoveredBlockCount} uncovered BB(s)");
        if (fn.HasDangerousCalls && fn.DangerousCalls.Count > 0)
            parts.Add(string.Join(", ", fn.DangerousCalls.Take(3)));
        return string.Join(" · ", parts);
    }

    private static string BuildOracleDetail(OracleFindingDto f) =>
        $"{f.RuleClass} · {f.Severity} · iter #{f.Iteration}" +
        (string.IsNullOrWhiteSpace(f.Command) ? "" : $" · {f.Command}");

    private static int ScoreOracleFinding(OracleFindingDto f) =>
        ParseOracleSeverity(f.Severity) switch
        {
            OracleSeverity.Violation => 85,
            OracleSeverity.Runtime => 70,
            OracleSeverity.NearMiss => 45,
            _ => 25,
        };

    private static OracleScore BuildFrontierScoreBreakdown(FrontierBranchDto f)
    {
        var terms = new List<OracleScoreTerm>
        {
            new("frontier rank", f.Score, f.Kind),
        };
        if (f.CfgDistance > 0)
            terms.Add(new OracleScoreTerm("CFG distance", Math.Min(12, (int)Math.Round(f.CfgDistance * 3)), $"{f.CfgDistance} hop(s)"));
        if (f.Rarity > 0)
            terms.Add(new OracleScoreTerm("rarity", Math.Min(10, (int)Math.Round(f.Rarity * 10)), $"{f.Rarity:P0}"));
        if (f.UnseenSuccessorCount > 0)
            terms.Add(new OracleScoreTerm("unseen successors", Math.Min(12, f.UnseenSuccessorCount * 3),
                $"{f.UnseenSuccessorCount}"));
        if (f.SinkProximity > 0)
            terms.Add(new OracleScoreTerm("sink proximity", Math.Min(15, (int)Math.Round(f.SinkProximity * 15)),
                $"{f.SinkProximity:P0}"));

        var total = Math.Min(100, terms.Sum(t => t.Points));
        return new OracleScore(total, terms, f.Detail);
    }

    private static OracleScore BuildStaticScoreBreakdown(
        RandallAnalysisFunctionDto fn,
        RandallAnalysisDocument? analysis)
    {
        var terms = new List<OracleScoreTerm>
        {
            new("fuzz priority", fn.FuzzPriority, $"{fn.FuzzPriority}/100"),
        };
        if (fn.HasDangerousCalls && fn.DangerousCalls.Count > 0)
        {
            terms.Add(new OracleScoreTerm(
                "dangerous calls",
                Math.Min(15, fn.DangerousCalls.Count * 5),
                string.Join(", ", fn.DangerousCalls.Take(4))));
        }

        if (fn.UncoveredBlockCount > 0)
        {
            terms.Add(new OracleScoreTerm(
                "coverage gap",
                Math.Min(20, fn.UncoveredBlockCount * 4),
                $"{fn.UncoveredBlockCount} uncovered BB(s)"));
        }
        else if (fn.CoverageFraction is < 1.0)
        {
            terms.Add(new OracleScoreTerm(
                "partial coverage",
                Math.Min(12, (int)Math.Round((1.0 - fn.CoverageFraction.Value) * 12)),
                $"{fn.CoverageFraction:P0} covered"));
        }

        if (fn.InputReachable)
            terms.Add(new OracleScoreTerm("input reachable", 8, "from entry"));

        var staticBonus = GhidraAnalysisOracleHints.StaticMapScoreBonus(fn.Name, analysis);
        if (staticBonus > 0)
            terms.Add(new OracleScoreTerm("static map bias", staticBonus, "oracle companion"));

        var total = Math.Min(100, terms.Sum(t => t.Points));
        return new OracleScore(total, terms, BuildStaticDetail(fn));
    }

    private static OracleScore BuildOracleScoreBreakdown(OracleFindingDto f)
    {
        var terms = new List<OracleScoreTerm>();
        var sev = ParseOracleSeverity(f.Severity);
        if (sev >= OracleSeverity.Violation)
            terms.Add(new OracleScoreTerm("violation", 35, f.RuleId));
        else if (sev >= OracleSeverity.NearMiss)
            terms.Add(new OracleScoreTerm("near miss", 12, f.RuleId));
        else if (sev >= OracleSeverity.Runtime)
            terms.Add(new OracleScoreTerm("runtime signal", 25, f.RuleId));

        if (!string.IsNullOrWhiteSpace(f.RuleClass))
            terms.Add(new OracleScoreTerm("rule class", 10, f.RuleClass));

        if (f.Confidence >= 0.7)
            terms.Add(new OracleScoreTerm("confidence", (int)Math.Round(f.Confidence * 10), $"{f.Confidence:P0}"));

        if (terms.Count == 0)
            terms.Add(new OracleScoreTerm("oracle hint", ScoreOracleFinding(f), f.RuleId));

        var total = Math.Min(100, terms.Sum(t => t.Points));
        return new OracleScore(total, terms, BuildOracleDetail(f));
    }

    private static OracleSeverity ParseOracleSeverity(string s) =>
        s.Trim().ToLowerInvariant() switch
        {
            "runtime" => OracleSeverity.Runtime,
            "violation" => OracleSeverity.Violation,
            "nearmiss" or "near_miss" or "near-miss" => OracleSeverity.NearMiss,
            _ => OracleSeverity.None,
        };

    private static string BuildSummary(
        FrontierReportDto? frontier,
        GhidraAnalysisOracleHints.HintPack? hints,
        int oracleCount,
        IReadOnlyList<StalkIntelligenceTargetDto> targets)
    {
        if (targets.Count == 0 && frontier is null && hints is null && oracleCount == 0)
            return "Randall is waiting for stalk data — no gray doors or static map yet.";

        var parts = new List<string>();
        if (frontier?.FrontierCount > 0)
            parts.Add($"{frontier.FrontierCount} gray door(s)");
        if (hints is not null)
            parts.Add(hints.Summary);
        if (oracleCount > 0)
            parts.Add($"{oracleCount} recent oracle hint(s)");
        if (targets.Count > 0)
            parts.Add($"top pick: {targets[0].Label} [{targets[0].Score}]");

        return parts.Count == 0 ? "Stalk artifacts loaded — bias seeds toward uncovered surfaces." : string.Join(" · ", parts);
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

    private static (IReadOnlyList<MutatorCreditRowDto> Rows, bool BiasEnabled) TryLoadLatestMutatorCredits(
        string project,
        string repoRoot)
    {
        var yaml = FindProjectYaml(repoRoot, project);
        if (yaml is null)
            return ([], true);

        try
        {
            var cfg = ProjectLoader.Load(yaml);
            var runsRoot = ProjectLoader.ResolvePath(yaml, cfg.Fuzz.RunsDir);
            if (!Directory.Exists(runsRoot))
                return ([], cfg.Fuzz.MutatorCredit);

            string? bestRunDir = null;
            DateTimeOffset bestAt = default;
            foreach (var dir in Directory.EnumerateDirectories(runsRoot)
                         .Where(d => Path.GetFileName(d).StartsWith(project + "_", StringComparison.OrdinalIgnoreCase)))
            {
                var statsPath = Path.Combine(dir, "mutator_stats.json");
                if (!File.Exists(statsPath))
                    continue;
                var manifestPath = Path.Combine(dir, "run.json");
                var at = File.Exists(manifestPath)
                    ? (JsonSerializer.Deserialize<FuzzRunManifestDto>(File.ReadAllText(manifestPath), JsonOptions)?.StartedAt
                       ?? new DateTimeOffset(File.GetLastWriteTimeUtc(dir)))
                    : new DateTimeOffset(File.GetLastWriteTimeUtc(dir));
                if (bestRunDir is null || at > bestAt)
                {
                    bestRunDir = dir;
                    bestAt = at;
                }
            }

            if (bestRunDir is null)
                return ([], cfg.Fuzz.MutatorCredit);

            var dto = JsonSerializer.Deserialize<MutatorCreditRunDto>(
                File.ReadAllText(Path.Combine(bestRunDir, "mutator_stats.json")), JsonOptions);
            return (dto?.Mutators ?? [], dto?.BiasEnabled ?? cfg.Fuzz.MutatorCredit);
        }
        catch
        {
            return ([], true);
        }
    }

    private static string? FindProjectYaml(string repoRoot, string project)
    {
        var name = project.Trim();
        foreach (var candidate in new[]
                 {
                     Path.Combine(repoRoot, "projects", name + ".yaml"),
                     Path.Combine(repoRoot, "projects", name + ".yml"),
                     Path.Combine(repoRoot, "projects", "local", name + ".yaml"),
                 })
        {
            if (File.Exists(candidate))
                return candidate;
        }

        foreach (var path in ProjectLoader.DiscoverAll(repoRoot))
        {
            try
            {
                var p = ProjectLoader.Load(path);
                if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase))
                    return path;
            }
            catch
            {
                /* ignore */
            }
        }

        return null;
    }
}
