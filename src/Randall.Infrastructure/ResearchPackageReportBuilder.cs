using System.Text;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// RF-#### research package builder — assembles a teaching report from crash evidence
/// (target, discovery, ancestry, repro, debugger, root cause, influence, primitive,
/// mitigations, experiments, confirmed/disproven, maturity, open questions, remediation).
/// Research-only; never emits shellcode, ROP, or auto-applied patches.
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

    public static string FormatReportId(Guid crashId) =>
        "RF-" + crashId.ToString("N")[..8].ToUpperInvariant();

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

    public static ResearchPackageReportDto? TryReadForCrash(string crashesDir, Guid crashId) =>
        TryRead(PathForCrash(crashesDir, crashId));

    public static ResearchPackageReportDto BuildForCrash(
        Guid crashId,
        string project,
        ExploitabilityAdvisorDto? advisor = null,
        ResearchPlanDto? plan = null,
        PatchHypothesisDto? patchHypothesis = null,
        BarrierReportDto? barriers = null,
        CrashSidecarDto? sidecar = null,
        CrashTriageDto? triage = null,
        DebuggerObservation? debugger = null,
        RootCauseAnalysisDto? rootCause = null,
        CrashInfluenceMapDto? influence = null,
        CrashPrimitiveReportDto? primitives = null,
        HypothesisSetDto? hypotheses = null,
        SkepticReportDto? skeptic = null,
        CounterfactualReportDto? counterfactual = null,
        CrashCorruptionChainDto? corruption = null,
        string? targetPath = null,
        string? targetVersion = null,
        byte[]? payload = null,
        string? inputPath = null,
        string? inputHash = null)
    {
        var reportId = FormatReportId(crashId);
        var packages = BuildStudyChecklist(crashId, advisor, plan, patchHypothesis, barriers);
        var experiments = CollectExperiments(hypotheses, skeptic, counterfactual, plan);
        var (confirmed, disproven) = CollectVerdicts(hypotheses, skeptic);
        var openQuestions = CollectOpenQuestions(rootCause, influence, primitives, skeptic, counterfactual);
        var maturity = primitives is not null
            ? $"{primitives.Maturity} · {primitives.MaturityLabel}"
            : triage is not null ? "R1 · Triaged" : "R0 · Crash";

        var target = !string.IsNullOrWhiteSpace(targetPath)
            ? Path.GetFileName(targetPath)
            : !string.IsNullOrWhiteSpace(sidecar?.TargetDetail)
                ? Truncate(sidecar!.TargetDetail, 80)
                : project;
        var discovery = BuildDiscovery(sidecar, triage, corruption);
        var ancestry = BuildAncestry(sidecar, corruption);
        var repro = BuildMinimalRepro(crashId, payload, inputPath ?? sidecar?.InputPath, inputHash ?? sidecar?.InputHash, sidecar);
        var dbg = BuildDebuggerEvidence(debugger, triage);
        var rootText = BuildRootCauseText(rootCause);
        var influenceText = BuildInfluenceText(influence);
        var primitiveText = BuildPrimitiveText(primitives);
        var mitigations = BuildMitigations(debugger, rootCause, patchHypothesis, advisor);
        var remediation = BuildRemediation(patchHypothesis, rootCause, primitives);

        var confidence = advisor?.Confidence
            ?? primitives?.Confidence
            ?? (plan is { Ok: true } ? plan.Confidence : "LOW");

        var summary =
            $"{reportId}: {maturity} — {Truncate(rootCause?.EducationalSummary ?? discovery ?? "crash research package", 160)}. " +
            "Teaching report only; no weaponization.";

        return new ResearchPackageReportDto(
            true,
            project,
            crashId,
            reportId,
            summary,
            target,
            targetVersion,
            discovery,
            ancestry,
            repro,
            dbg,
            rootText,
            influenceText,
            primitiveText,
            mitigations,
            experiments,
            confirmed,
            disproven,
            maturity,
            openQuestions,
            remediation,
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
        BarrierReportDto? barriers = null,
        CrashSidecarDto? sidecar = null,
        CrashTriageDto? triage = null,
        DebuggerObservation? debugger = null,
        RootCauseAnalysisDto? rootCause = null,
        CrashInfluenceMapDto? influence = null,
        CrashPrimitiveReportDto? primitives = null,
        HypothesisSetDto? hypotheses = null,
        SkepticReportDto? skeptic = null,
        CounterfactualReportDto? counterfactual = null,
        CrashCorruptionChainDto? corruption = null,
        string? targetPath = null,
        string? targetVersion = null,
        byte[]? payload = null,
        string? inputPath = null,
        string? inputHash = null)
    {
        var report = BuildForCrash(
            crashId, project, advisor, plan, patchHypothesis, barriers,
            sidecar, triage, debugger, rootCause, influence, primitives,
            hypotheses, skeptic, counterfactual, corruption,
            targetPath, targetVersion, payload, inputPath, inputHash);
        Directory.CreateDirectory(crashesDir);
        File.WriteAllText(PathForCrash(crashesDir, crashId), JsonSerializer.Serialize(report, JsonOpts));

        try
        {
            var stalkDir = Path.GetDirectoryName(PathForProject(CrashCatalog.FindRepoRoot(), project));
            if (!string.IsNullOrEmpty(stalkDir))
            {
                Directory.CreateDirectory(stalkDir);
                File.WriteAllText(
                    PathForProject(CrashCatalog.FindRepoRoot(), project),
                    JsonSerializer.Serialize(report, JsonOpts));
            }
        }
        catch
        {
            /* campaign rollup is best-effort */
        }

        return report;
    }

    /// <summary>Markdown export for CLI/API — conceptual teaching report only.</summary>
    public static string ToMarkdown(ResearchPackageReportDto report)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# {report.ReportId} — Research Package");
        sb.AppendLine();
        sb.AppendLine($"**Project:** {report.Project}");
        if (report.CrashId is Guid cid)
            sb.AppendLine($"**Crash:** `{cid:N}`");
        sb.AppendLine($"**Maturity:** {report.Maturity ?? "?"}");
        sb.AppendLine($"**Confidence:** {report.Confidence}");
        sb.AppendLine($"**At:** {report.At:u}");
        sb.AppendLine();
        sb.AppendLine(report.Summary);
        sb.AppendLine();
        Section(sb, "Target", report.Target, report.TargetVersion);
        Section(sb, "Discovery", report.Discovery);
        Section(sb, "Mutation ancestry", report.MutationAncestry);
        Section(sb, "Minimal repro", report.MinimalRepro);
        Section(sb, "Debugger evidence", report.DebuggerEvidence);
        Section(sb, "Root cause", report.RootCause);
        Section(sb, "Influence", report.Influence);
        Section(sb, "Primitive", report.Primitive);
        Section(sb, "Mitigations", report.Mitigations);
        if (report.Experiments.Count > 0)
        {
            sb.AppendLine("## Experiments");
            foreach (var e in report.Experiments)
                sb.AppendLine($"- **{e.Kind}** `{e.Id}` [{e.Outcome}] — {e.Description}" +
                              (string.IsNullOrWhiteSpace(e.Detail) ? "" : $" ({e.Detail})"));
            sb.AppendLine();
        }
        if (report.Confirmed.Count > 0)
        {
            sb.AppendLine("## Confirmed");
            foreach (var c in report.Confirmed) sb.AppendLine($"- {c}");
            sb.AppendLine();
        }
        if (report.Disproven.Count > 0)
        {
            sb.AppendLine("## Disproven");
            foreach (var d in report.Disproven) sb.AppendLine($"- {d}");
            sb.AppendLine();
        }
        if (report.OpenQuestions.Count > 0)
        {
            sb.AppendLine("## Open questions");
            foreach (var q in report.OpenQuestions) sb.AppendLine($"- {q}");
            sb.AppendLine();
        }
        Section(sb, "Suggested remediation (conceptual)", report.SuggestedRemediation);
        sb.AppendLine("## Study checklist");
        foreach (var p in report.Packages.OrderBy(x => x.Priority))
            sb.AppendLine($"- ({p.Priority}) **{p.Title}** — {p.Description}");
        sb.AppendLine();
        sb.AppendLine("> Research/teaching only — no shellcode, ROP chains, or auto-exploit packages.");
        return sb.ToString();
    }

    private static void Section(StringBuilder sb, string title, string? body, string? extra = null)
    {
        if (string.IsNullOrWhiteSpace(body) && string.IsNullOrWhiteSpace(extra))
            return;
        sb.AppendLine($"## {title}");
        if (!string.IsNullOrWhiteSpace(body)) sb.AppendLine(body);
        if (!string.IsNullOrWhiteSpace(extra)) sb.AppendLine($"Version/build: {extra}");
        sb.AppendLine();
    }

    private static List<ResearchPackageItemDto> BuildStudyChecklist(
        Guid crashId,
        ExploitabilityAdvisorDto? advisor,
        ResearchPlanDto? plan,
        PatchHypothesisDto? patchHypothesis,
        BarrierReportDto? barriers)
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
                [$"crash:{crashId:N}"]));
        }

        packages.Add(new ResearchPackageItemDto(
            "pkg-ethics",
            "Research ethics reminder",
            "Study depth and mitigations only — no shellcode, ROP chains, or auto-exploit packages.",
            99,
            []));

        return packages;
    }

    private static List<ResearchPackageExperimentDto> CollectExperiments(
        HypothesisSetDto? hypotheses,
        SkepticReportDto? skeptic,
        CounterfactualReportDto? counterfactual,
        ResearchPlanDto? plan)
    {
        var list = new List<ResearchPackageExperimentDto>();

        if (hypotheses?.Hypotheses is { Count: > 0 })
        {
            foreach (var h in hypotheses.Hypotheses.Where(h => h.Result is not null).Take(8))
            {
                list.Add(new ResearchPackageExperimentDto(
                    h.Id,
                    h.Experiment.Kind.ToString(),
                    h.Statement,
                    h.Status.ToString(),
                    h.Result?.Observation));
            }
        }

        if (counterfactual is { Ok: true, LiveExecuted: true })
        {
            list.Add(new ResearchPackageExperimentDto(
                "counterfactual-live",
                "Counterfactual",
                Truncate(counterfactual.Summary, 160),
                counterfactual.SmallestSafeChange is not null ? "BoundaryFound" : "Mapped",
                $"{counterfactual.SafeAdjacentCount} safe / {counterfactual.StillCorruptCount} corrupt"));
        }

        if (skeptic?.Challenges is { Count: > 0 })
        {
            foreach (var c in skeptic.Challenges.Where(c => c.Status != SkepticChallengeStatus.Proposed).Take(6))
            {
                list.Add(new ResearchPackageExperimentDto(
                    c.Id,
                    "Skeptic",
                    Truncate(c.ClaimStatement, 120),
                    c.Status.ToString(),
                    c.Observation));
            }
        }

        if (list.Count == 0 && plan is { Ok: true, Steps.Count: > 0 })
        {
            foreach (var step in plan.Steps.Take(4))
            {
                list.Add(new ResearchPackageExperimentDto(
                    $"plan-step-{step.Order}",
                    step.Experiment.Kind.ToString(),
                    step.Experiment.Description,
                    "Planned",
                    step.Rationale));
            }
        }

        return list;
    }

    private static (List<string> Confirmed, List<string> Disproven) CollectVerdicts(
        HypothesisSetDto? hypotheses,
        SkepticReportDto? skeptic)
    {
        var confirmed = new List<string>();
        var disproven = new List<string>();

        if (hypotheses?.Hypotheses is { Count: > 0 })
        {
            foreach (var h in hypotheses.Hypotheses)
            {
                if (h.Status == HypothesisStatus.Confirmed)
                    confirmed.Add($"Hypothesis {h.Id}: {Truncate(h.Statement, 140)}");
                else if (h.Status == HypothesisStatus.Refuted)
                    disproven.Add($"Hypothesis {h.Id}: {Truncate(h.Statement, 140)}");
            }
        }

        if (skeptic?.Challenges is { Count: > 0 })
        {
            foreach (var c in skeptic.Challenges)
            {
                if (c.Status == SkepticChallengeStatus.Survived)
                    confirmed.Add($"Skeptic {c.Id} survived: {Truncate(c.ClaimStatement, 140)}");
                else if (c.Status == SkepticChallengeStatus.Falsified)
                    disproven.Add($"Skeptic {c.Id} falsified: {Truncate(c.ClaimStatement, 140)}");
            }
        }

        return (confirmed, disproven);
    }

    private static List<string> CollectOpenQuestions(
        RootCauseAnalysisDto? rootCause,
        CrashInfluenceMapDto? influence,
        CrashPrimitiveReportDto? primitives,
        SkepticReportDto? skeptic,
        CounterfactualReportDto? counterfactual)
    {
        var qs = new List<string>();
        if (rootCause?.Candidate.Unknowns is { Count: > 0 })
            qs.AddRange(rootCause.Candidate.Unknowns.Take(3).Select(u => $"Root-cause unknown: {u}"));
        if (influence is not { Ok: true, Links.Count: > 0 })
            qs.Add("Which input region most strongly influences the faulting state?");
        if (primitives is null || primitives.Maturity < ResearchMaturity.R5)
            qs.Add("Can an independent Skeptic neutralize/replay confirm the primitive observation?");
        if (skeptic is null || !EvidenceCourt.PassesPromotionGate(skeptic, primitives?.Facts))
            qs.Add("Run Skeptic + cite ≥1 EvidenceFact (Court gate for CONFIRMED / R5+).");
        if (counterfactual is not { LiveExecuted: true })
            qs.Add("Map adjacent safe vs corrupt with a live counterfactual re-exec.");
        if (qs.Count == 0)
            qs.Add("Document remediation conceptually and verify on a patched lab build.");
        return qs.Distinct().Take(8).ToList();
    }

    private static string BuildDiscovery(CrashSidecarDto? sidecar, CrashTriageDto? triage, CrashCorruptionChainDto? corruption)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(sidecar?.Mutator))
            parts.Add($"mutator={sidecar.Mutator}");
        if (sidecar?.Iteration is int it)
            parts.Add($"iteration={it}");
        if (!string.IsNullOrWhiteSpace(sidecar?.RunId))
            parts.Add($"run={sidecar.RunId}");
        if (!string.IsNullOrWhiteSpace(triage?.Severity))
            parts.Add($"severity={triage.Severity}");
        if (!string.IsNullOrWhiteSpace(corruption?.SuspectedMutator))
            parts.Add($"corruption-mutator={corruption.SuspectedMutator}");
        return parts.Count > 0 ? string.Join(", ", parts) : "Crash recorded during fuzz/research campaign.";
    }

    private static string? BuildAncestry(CrashSidecarDto? sidecar, CrashCorruptionChainDto? corruption)
    {
        if (sidecar?.MutatorChain is { Count: > 0 })
            return "Mutator chain: " + string.Join(" → ", sidecar.MutatorChain.Take(12));
        if (corruption?.Steps is { Count: > 0 })
            return "Corruption steps: " + string.Join(" → ", corruption.Steps.Take(6).Select(s => s.Label));
        if (!string.IsNullOrWhiteSpace(sidecar?.ParentInputHash))
            return $"Parent input hash: {sidecar.ParentInputHash}";
        return null;
    }

    private static string BuildMinimalRepro(
        Guid crashId,
        byte[]? payload,
        string? inputPath,
        string? inputHash,
        CrashSidecarDto? sidecar)
    {
        var parts = new List<string> { $"crash={crashId:N}" };
        if (!string.IsNullOrWhiteSpace(inputHash ?? sidecar?.InputHash))
            parts.Add($"hash={inputHash ?? sidecar!.InputHash}");
        if (payload is { Length: > 0 })
            parts.Add($"bytes={payload.Length}");
        if (!string.IsNullOrWhiteSpace(inputPath))
            parts.Add($"path={inputPath}");
        parts.Add("Replay via `randall replay -i <guid>` (lab targets only).");
        return string.Join("; ", parts);
    }

    private static string? BuildDebuggerEvidence(DebuggerObservation? debugger, CrashTriageDto? triage)
    {
        if (debugger is { Ok: true })
        {
            return $"access={debugger.Access}, addressClass={debugger.FaultAddressClass}, " +
                   $"influence={debugger.SuspectedInputInfluence}" +
                   (string.IsNullOrWhiteSpace(debugger.ExceptionCode) ? "" : $", exception={debugger.ExceptionCode}");
        }

        if (triage is not null)
            return $"triage severity={triage.Severity}, class={triage.Class}";
        return null;
    }

    private static string? BuildRootCauseText(RootCauseAnalysisDto? rootCause)
    {
        if (rootCause is not { Ok: true }) return null;
        var c = rootCause.Candidate;
        return $"{c.Category} [{c.Confidence}] @ {c.FaultingFunction ?? "?"} " +
               $"sink={c.SuspectedSink ?? "?"} region={c.InputRegion ?? "?"} — " +
               Truncate(rootCause.EducationalSummary, 200);
    }

    private static string? BuildInfluenceText(CrashInfluenceMapDto? influence)
    {
        if (influence is not { Ok: true, Links.Count: > 0 }) return null;
        var top = influence.Links
            .OrderByDescending(l => l.Status)
            .First();
        return $"{influence.Links.Count} link(s) [{influence.Confidence}]; top {top.Status}: " +
               $"{top.Region.StartOffset}+ → {top.State.Kind}/{top.State.Label} ({top.Mechanism})";
    }

    private static string? BuildPrimitiveText(CrashPrimitiveReportDto? primitives)
    {
        if (primitives is null) return null;
        var top = primitives.Primitives
            .OrderByDescending(p => p.State)
            .ThenByDescending(p => p.Confidence)
            .FirstOrDefault();
        return top is null
            ? $"{primitives.Maturity} · {primitives.MaturityLabel} — no capabilities assessed"
            : $"{primitives.Maturity} · {primitives.MaturityLabel}: {top.Kind} [{top.State}] — {Truncate(top.Mechanism, 120)}";
    }

    private static string BuildMitigations(
        DebuggerObservation? debugger,
        RootCauseAnalysisDto? rootCause,
        PatchHypothesisDto? patchHypothesis,
        ExploitabilityAdvisorDto? advisor)
    {
        var parts = new List<string>();
        if (advisor?.OverallLabel is { } label)
            parts.Add($"advisor posture: {label}");
        if (rootCause?.Candidate.Category is RootCauseCategory.BoundsViolation)
            parts.Add("Study bounds checks / length validation before copy sinks.");
        if (rootCause?.Candidate.Category is RootCauseCategory.LifetimeViolation
            or RootCauseCategory.UnexpectedObjectState)
            parts.Add("Study object lifetime / free-list hygiene (lab heap hardening).");
        if (debugger?.FaultAddressClass == DebuggerAddressClass.AsciiPattern)
            parts.Add("ASCII-controlled address — prioritize input→pointer attribution study.");
        if (patchHypothesis is { Ok: true })
            parts.Add("See patch-hypothesis remediation text (conceptual; not auto-applied).");
        if (parts.Count == 0)
            parts.Add("Run checksec / mitigation ladder on the lab target; document NX/ASLR/canary posture.");
        return string.Join(" ", parts);
    }

    private static string BuildRemediation(
        PatchHypothesisDto? patchHypothesis,
        RootCauseAnalysisDto? rootCause,
        CrashPrimitiveReportDto? primitives)
    {
        if (patchHypothesis is { Ok: true } && !string.IsNullOrWhiteSpace(patchHypothesis.RemediationText))
            return Truncate(patchHypothesis.RemediationText, 400) +
                   " (Conceptual only — verify on a patched lab build; Randall does not apply patches.)";

        if (rootCause?.Candidate.Category is RootCauseCategory.BoundsViolation)
            return "Conceptually: validate length against destination capacity before copy; " +
                   "add regression oracle for the minimal repro. Do not auto-apply patches.";

        if (primitives?.Primitives.Any(p => p.Kind == PrimitiveKind.ObjectLifetimeInfluence) == true)
            return "Conceptually: ensure lifetimes are tied to ownership; poison-on-free in lab builds. " +
                   "Teaching remediation only — no patch apply.";

        return "Document a conceptual fix aligned with the root-cause category and re-fuzz the patched lab binary. " +
               "Randall never auto-applies patches or emits exploit payloads.";
    }

    private static string Truncate(string? text, int max) =>
        string.IsNullOrEmpty(text) ? "" : text.Length <= max ? text : text[..max] + "…";
}
