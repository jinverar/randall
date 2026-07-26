using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Wave 7 research package / report stub — rolls advisor packages, planner steps,
/// and barrier hints into a single teaching checklist. No weaponization.
/// </summary>
public static class ResearchPackageReportBuilder
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    public static string PathForCrash(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_research_package.json");

    public static string PathForProject(string? repoRoot, string project) =>
        Path.Combine(repoRoot ?? ".", "data", "stalk", project, "research_package_last.json");

    public static ResearchPackageReportDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<ResearchPackageReportDto>(File.ReadAllText(path), JsonOpts);
        }
        catch
        {
            return null;
        }
    }

    public static ResearchPackageReportDto BuildForCrash(
        Guid crashId,
        string project,
        ExploitabilityAdvisorDto? advisor = null,
        ResearchPlanDto? plan = null,
        PatchHypothesisDto? patchHypothesis = null,
        BarrierReportDto? barriers = null)
    {
        var packages = new List<ResearchPackageItemDto>();
        var priority = 1;

        if (advisor?.RecommendedPackages is { Count: > 0 })
        {
            foreach (var name in advisor.RecommendedPackages.Take(6))
            {
                packages.Add(new ResearchPackageItemDto(
                    $"pkg-advisor-{priority}",
                    name,
                    advisor.Rationale.ElementAtOrDefault(priority - 1)
                        ?? $"Study package from ExploitabilityAdvisor ({advisor.OverallLabel}).",
                    priority++,
                    advisor.EvidenceRefs.Take(4).ToList()));
            }
        }

        if (plan is { Ok: true, Steps.Count: > 0 })
        {
            packages.Add(new ResearchPackageItemDto(
                "pkg-research-plan",
                "Execute research plan steps",
                $"{plan.Steps.Count} ordered experiment step(s): {plan.Objective}",
                priority++,
                plan.Claims.Select(c => c.Id).Take(4).ToList()));
        }

        if (patchHypothesis is { Ok: true })
        {
            packages.Add(new ResearchPackageItemDto(
                "pkg-patch-hypothesis",
                "Remediation study + patched-lab verify hook",
                Truncate(patchHypothesis.RemediationText, 220),
                priority++,
                patchHypothesis.EvidenceRefs.Take(4).ToList()));
        }

        if (barriers?.Barriers is { Count: > 0 })
        {
            packages.Add(new ResearchPackageItemDto(
                "pkg-barriers",
                "Clear campaign barriers",
                string.Join("; ", barriers.Barriers.Take(3).Select(b => b.Diagnosis)),
                priority++,
                barriers.Barriers.Select(b => b.Id).Take(4).ToList()));
        }

        if (packages.Count == 0)
        {
            packages.Add(new ResearchPackageItemDto(
                "pkg-baseline-triage",
                "Baseline crash triage",
                "Capture debugger observation, root-cause, and influence before packaging deeper study.",
                1,
                []));
        }

        packages.Add(new ResearchPackageItemDto(
            "pkg-ethics",
            "Research ethics reminder",
            "Study depth and mitigations only — no shellcode, ROP chains, or auto-exploit packages.",
            99,
            []));

        var confidence = advisor?.Confidence
            ?? (plan is { Ok: true } ? plan.Confidence : "LOW");
        var summary =
            $"{packages.Count} research package item(s) for crash {crashId.ToString("N")[..8]}… " +
            "Teaching checklist only.";

        return new ResearchPackageReportDto(
            true,
            project,
            crashId,
            summary,
            packages.OrderBy(p => p.Priority).ToList(),
            confidence,
            DateTimeOffset.UtcNow);
    }

    public static ResearchPackageReportDto PersistForCrash(
        string crashesDir,
        Guid crashId,
        string project,
        ExploitabilityAdvisorDto? advisor = null,
        ResearchPlanDto? plan = null,
        PatchHypothesisDto? patchHypothesis = null,
        BarrierReportDto? barriers = null)
    {
        var report = BuildForCrash(crashId, project, advisor, plan, patchHypothesis, barriers);
        Directory.CreateDirectory(crashesDir);
        File.WriteAllText(PathForCrash(crashesDir, crashId), JsonSerializer.Serialize(report, JsonOpts));
        return report;
    }

    private static string Truncate(string? text, int max) =>
        string.IsNullOrEmpty(text) ? "" : text.Length <= max ? text : text[..max] + "…";
}
