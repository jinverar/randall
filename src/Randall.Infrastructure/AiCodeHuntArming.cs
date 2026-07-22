using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Called from <see cref="FuzzEngine"/> when <c>aiCode.enabled</c> — scan + arm oracles/dict
/// so the campaign actively hunts AI-codegen bugs.
/// </summary>
public static class AiCodeHuntArming
{
    public static AiCodeHuntPlanDto? ArmForFuzz(
        ProjectConfig project,
        string yamlPath,
        IFuzzProgressSink? progress)
    {
        if (project.AiCode is not { Enabled: true } cfg)
            return null;

        if (cfg.AutoArmOracles)
        {
            project.Oracles = AiCodeOraclePack.MergeInto(project.Oracles);
            FuzzAnalystLog.Info(progress,
                "AI hunt: armed semantic oracle pack (auth/state/integer/structure/resource)");
        }

        if (cfg.AutoArmDictionary)
        {
            if (string.IsNullOrWhiteSpace(project.DictionaryFile))
                project.DictionaryFile = AiCodeOraclePack.DictionaryRelativePath;
            foreach (var m in AiCodeOraclePack.RecommendedMutators())
            {
                if (!project.Mutators.Any(x => x.Equals(m, StringComparison.OrdinalIgnoreCase)))
                    project.Mutators.Add(m);
            }

            // Merge tokens into inline dictionary as a safety net if file missing.
            var dictPath = ProjectLoader.ResolvePath(yamlPath, project.DictionaryFile!);
            if (!File.Exists(dictPath))
            {
                foreach (var tok in AiCodeMistakes.DefaultDictionaryTokens())
                {
                    if (!project.Dictionary.Contains(tok, StringComparer.Ordinal))
                        project.Dictionary.Add(tok);
                }
                FuzzAnalystLog.Warn(progress,
                    $"AI hunt: dictionary file missing ({dictPath}) — using built-in AI-mistake tokens");
            }
            else
            {
                FuzzAnalystLog.Info(progress, $"AI hunt: dictionary → {dictPath}");
            }
        }

        if (!cfg.ScanOnFuzzStart || cfg.SourceRoots.Count == 0)
        {
            FuzzAnalystLog.Info(progress,
                "AI hunt: oracles/dict armed (set aiCode.sourceRoots to prioritize AI blocks on start)");
            return null;
        }

        AiCodeHuntPlanDto? last = null;
        foreach (var rootRel in cfg.SourceRoots)
        {
            var root = ProjectLoader.ResolvePath(yamlPath, rootRel);
            if (!Directory.Exists(root))
            {
                FuzzAnalystLog.Warn(progress, $"AI hunt: source root missing → {root}");
                continue;
            }

            try
            {
                var scan = AiCodeAttribution.Scan(root, cfg.Extensions);
                var plan = AiCodeHunt.BuildPlan(scan);
                last = plan;
                FuzzAnalystLog.Info(progress, $"AI hunt: {plan.Summary}");
                foreach (var b in plan.PriorityAiBlocks.Take(8))
                {
                    FuzzAnalystLog.Info(progress,
                        $"  AI block {b.Path}:{b.StartLine}-{b.EndLine} ({b.Confidence:0.00}) — focus oracles on this code");
                }

                if (cfg.PersistReport)
                {
                    var outDir = Path.Combine(
                        ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CorpusDir),
                        "_ai_code");
                    var path = AiCodeAttribution.PersistReport(scan, outDir);
                    var huntMd = Path.Combine(outDir, "hunt_plan.md");
                    File.WriteAllText(huntMd, AiCodeHunt.RenderPlanMarkdown(plan));
                    FuzzAnalystLog.Info(progress, $"AI hunt report → {path}");
                }
            }
            catch (Exception ex)
            {
                FuzzAnalystLog.Warn(progress, $"AI hunt scan failed for {root}: {ex.Message}");
            }
        }

        return last;
    }
}
