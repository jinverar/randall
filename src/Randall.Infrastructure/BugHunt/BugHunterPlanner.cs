using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure.BugHunt;

/// <summary>
/// Turn an attribution scan into an active hunt plan for AI-authored bad code.
/// </summary>
public static class BugHunterPlanner
{
    public static BugHunterPlanDto BuildPlan(BugHunterScanDto scan)
    {
        var aiBlocks = scan.Blocks
            .Where(b => b.Provenance is BugHunterProvenance.LikelyAi or BugHunterProvenance.AnnotatedAi)
            .OrderByDescending(b => b.Confidence)
            .ThenByDescending(b => b.EndLine - b.StartLine)
            .ToList();

        var mistakes = scan.SuggestedMistakeClasses.Count > 0
            ? scan.SuggestedMistakeClasses
            : BugHunterMistakes.All.Where(m => m.Id != "mem-classic").Select(m => m.Id).Take(8).ToList();

        var focus = scan.SuggestedOracleFocus.Count > 0
            ? scan.SuggestedOracleFocus
            : (IReadOnlyList<string>)["auth", "state", "integer", "structure", "resource"];

        var summary = aiBlocks.Count == 0
            ? "No AI-attributed blocks found — hunt still arms semantic oracles; annotate with BEGIN AI for focus."
            : $"Hunt {aiBlocks.Count} AI-attributed block(s) across {aiBlocks.Select(b => b.Path).Distinct().Count()} file(s) for: {string.Join(", ", mistakes.Take(5))}.";

        return new BugHunterPlanDto(
            scan,
            aiBlocks.Take(40).ToList(),
            mistakes,
            focus,
            BugHunterOracleSuggestions.DictionaryRelativePath,
            summary);
    }

    public static string RenderPlanMarkdown(BugHunterPlanDto plan)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# AI bad-code hunt plan");
        sb.AppendLine();
        sb.AppendLine($"> {plan.Summary}");
        sb.AppendLine();
        sb.AppendLine($"Scanned: `{plan.Scan.Root}` · files={plan.Scan.FilesScanned} · AI blocks={plan.Scan.AiBlocks}");
        sb.AppendLine();
        sb.AppendLine("## Mistake classes");
        sb.AppendLine();
        sb.AppendLine("| Id | Channel | Title | Hunt |");
        sb.AppendLine("|----|---------|-------|------|");
        foreach (var id in plan.MistakeClasses)
        {
            var m = BugHunterMistakes.All.FirstOrDefault(x => x.Id == id);
            if (m is null)
            {
                sb.AppendLine($"| `{id}` | ? | | |");
                continue;
            }

            sb.AppendLine($"| `{m.Id}` | **{m.Channel}** | {m.Title} | {m.HuntWith} |");
        }

        sb.AppendLine();
        sb.AppendLine("## Oracle focus");
        foreach (var f in plan.OracleFocus)
            sb.AppendLine($"- `{f}`");
        sb.AppendLine();
        sb.AppendLine($"Dictionary: `{plan.DictionaryHint}`");
        sb.AppendLine();
        sb.AppendLine("## Priority AI code blocks");
        sb.AppendLine();
        sb.AppendLine("| File | Lines | Confidence | Signals |");
        sb.AppendLine("|------|-------|------------|---------|");
        foreach (var b in plan.PriorityAiBlocks)
        {
            sb.AppendLine(
                $"| `{b.Path}` | {b.StartLine}–{b.EndLine} | {b.Confidence:0.00} | {string.Join(", ", b.Signals.Take(3))} |");
        }

        sb.AppendLine();
        sb.AppendLine("## Previews (AI-attributed)");
        foreach (var b in plan.PriorityAiBlocks.Take(15))
        {
            sb.AppendLine();
            sb.AppendLine($"### `{b.Path}` L{b.StartLine}–{b.EndLine}");
            sb.AppendLine();
            sb.AppendLine("```" + b.Language);
            sb.AppendLine(b.Preview);
            sb.AppendLine("```");
        }

        return sb.ToString();
    }

    public static string RenderArmedYamlSnippet()
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Armed by Bug Hunter engine (docs/BUG_HUNTER.md)");
        sb.AppendLine("# Oracle engine remains judgment-only (docs/ORACLES.md)");
        sb.AppendLine("bugHunter:");
        sb.AppendLine("  enabled: true");
        sb.AppendLine("  scanOnFuzzStart: true");
        sb.AppendLine("  autoArmOracles: true   # suggest rules → Oracle engine");
        sb.AppendLine("  autoArmDictionary: true");
        sb.AppendLine("  sourceRoots:");
        sb.AppendLine("    - ../path/to/ai-written-src");
        sb.AppendLine("dictionaryFile: dictionaries/ai_codegen_mistakes.txt");
        sb.AppendLine("mutators:");
        foreach (var m in BugHunterOracleSuggestions.RecommendedMutators())
            sb.AppendLine($"  - {m}");
        sb.AppendLine("oracles:");
        sb.AppendLine("  enabled: true");
        sb.AppendLine("  # Bug Hunter fills empty auth/state/integer/structure/resource sections");
        return sb.ToString();
    }

    /// <summary>
    /// Arm a live <see cref="ProjectConfig"/> for Bug Hunter (suggests oracles + dict + mutators).
    /// </summary>
    public static string ArmProject(ProjectConfig project, string yamlPath, BugHunterPlanDto? plan = null)
    {
        project.BugHunter ??= new BugHunterConfig();
        project.BugHunter.Enabled = true;
        project.BugHunter.AutoArmOracles = true;
        project.BugHunter.AutoArmDictionary = true;
        project.BugHunter.ScanOnFuzzStart = true;

        project.Oracles = BugHunterOracleSuggestions.MergeInto(project.Oracles);

        if (string.IsNullOrWhiteSpace(project.DictionaryFile))
            project.DictionaryFile = BugHunterOracleSuggestions.DictionaryRelativePath;

        foreach (var m in BugHunterOracleSuggestions.RecommendedMutators())
        {
            if (!project.Mutators.Any(x => x.Equals(m, StringComparison.OrdinalIgnoreCase)))
                project.Mutators.Add(m);
        }

        var notes = new List<string>
        {
            "oracles←Bug Hunter suggestions",
            $"dictionary←{project.DictionaryFile}",
            $"mutators+=[{string.Join(',', BugHunterOracleSuggestions.RecommendedMutators())}]",
        };
        if (plan is not null)
            notes.Add($"priority AI blocks={plan.PriorityAiBlocks.Count}");
        _ = yamlPath;
        return string.Join(" · ", notes);
    }
}
