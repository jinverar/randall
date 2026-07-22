using Randall.Contracts;

namespace Randall.Infrastructure.BugHunt;

/// <summary>
/// Bug Hunter engine — AI/human code analysis, mistake catalog, hunt planning,
/// and campaign arming. Separate from <c>Oracles.OracleEngine</c>, which only judges
/// observations and reports findings.
/// </summary>
public static class BugHunterEngine
{
    /// <summary>True when the Bug Hunter project hook is enabled.</summary>
    public static bool IsEnabled(ProjectConfig project) =>
        project.BugHunter is { Enabled: true } || project.AiCode is { Enabled: true };

    public static BugHunterConfig? GetConfig(ProjectConfig project) =>
        project.BugHunter ?? project.AiCode;

    /// <summary>Attribute AI vs human regions in a source tree.</summary>
    public static BugHunterScanDto Scan(
        string root,
        IEnumerable<string>? extensions = null,
        int maxFiles = 2000) =>
        BugHunterAttribution.Scan(root, extensions, maxFiles);

    /// <summary>Build a hunt plan from an attribution scan.</summary>
    public static BugHunterPlanDto Plan(BugHunterScanDto scan) =>
        BugHunterPlanner.BuildPlan(scan);

    /// <summary>Scan + plan in one step.</summary>
    public static BugHunterPlanDto Analyze(
        string root,
        IEnumerable<string>? extensions = null) =>
        Plan(Scan(root, extensions));

    /// <summary>Mistake catalog (AI-codegen classes ↔ oracle/seed hints).</summary>
    public static IReadOnlyList<BugHunterMistakes.MistakeClass> Mistakes =>
        BugHunterMistakes.All;

    /// <summary>
    /// Called from <see cref="FuzzEngine"/> at campaign start: suggest oracle rules /
    /// dictionary / mutators, then surface priority AI-attributed blocks.
    /// Does not evaluate target behavior — that remains the Oracle engine.
    /// </summary>
    public static BugHunterPlanDto? PrepareForFuzz(
        ProjectConfig project,
        string yamlPath,
        IFuzzProgressSink? progress)
    {
        var cfg = GetConfig(project);
        if (cfg is not { Enabled: true })
            return null;

        // Ensure the preferred property is populated for the rest of the run.
        project.BugHunter ??= cfg;

        if (cfg.AutoArmOracles)
        {
            project.Oracles = BugHunterOracleSuggestions.MergeInto(project.Oracles);
            FuzzAnalystLog.Info(progress,
                "Bug Hunter: suggested oracle pack → Oracle engine (auth/state/integer/structure/resource)");
        }

        if (cfg.AutoArmDictionary)
        {
            if (string.IsNullOrWhiteSpace(project.DictionaryFile))
                project.DictionaryFile = BugHunterOracleSuggestions.DictionaryRelativePath;
            foreach (var m in BugHunterOracleSuggestions.RecommendedMutators())
            {
                if (!project.Mutators.Any(x => x.Equals(m, StringComparison.OrdinalIgnoreCase)))
                    project.Mutators.Add(m);
            }

            var dictPath = ProjectLoader.ResolvePath(yamlPath, project.DictionaryFile!);
            if (!File.Exists(dictPath))
            {
                foreach (var tok in BugHunterMistakes.DefaultDictionaryTokens())
                {
                    if (!project.Dictionary.Contains(tok, StringComparer.Ordinal))
                        project.Dictionary.Add(tok);
                }
                FuzzAnalystLog.Warn(progress,
                    $"Bug Hunter: dictionary file missing ({dictPath}) — using built-in mistake tokens");
            }
            else
            {
                FuzzAnalystLog.Info(progress, $"Bug Hunter: dictionary → {dictPath}");
            }
        }

        if (!cfg.ScanOnFuzzStart || cfg.SourceRoots.Count == 0)
        {
            FuzzAnalystLog.Info(progress,
                "Bug Hunter: campaign armed (set bugHunter.sourceRoots to prioritize AI blocks on start)");
            return null;
        }

        BugHunterPlanDto? last = null;
        foreach (var rootRel in cfg.SourceRoots)
        {
            var root = ProjectLoader.ResolvePath(yamlPath, rootRel);
            if (!Directory.Exists(root))
            {
                FuzzAnalystLog.Warn(progress, $"Bug Hunter: source root missing → {root}");
                continue;
            }

            try
            {
                var plan = Analyze(root, cfg.Extensions);
                last = plan;
                FuzzAnalystLog.Info(progress, $"Bug Hunter: {plan.Summary}");
                foreach (var b in plan.PriorityAiBlocks.Take(8))
                {
                    FuzzAnalystLog.Info(progress,
                        $"  AI block {b.Path}:{b.StartLine}-{b.EndLine} ({b.Confidence:0.00}) — prioritize this code");
                }

                if (cfg.PersistReport)
                {
                    var outDir = Path.Combine(
                        ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CorpusDir),
                        "_bug_hunter");
                    var path = BugHunterAttribution.PersistReport(plan.Scan, outDir);
                    var huntMd = Path.Combine(outDir, "hunt_plan.md");
                    File.WriteAllText(huntMd, BugHunterPlanner.RenderPlanMarkdown(plan));
                    FuzzAnalystLog.Info(progress, $"Bug Hunter report → {path}");
                }
            }
            catch (Exception ex)
            {
                FuzzAnalystLog.Warn(progress, $"Bug Hunter scan failed for {root}: {ex.Message}");
            }
        }

        return last;
    }

    /// <summary>Arm a project in-memory for a Bug Hunter campaign (CLI --arm).</summary>
    public static string ArmProject(ProjectConfig project, string yamlPath, BugHunterPlanDto? plan = null) =>
        BugHunterPlanner.ArmProject(project, yamlPath, plan);
}
