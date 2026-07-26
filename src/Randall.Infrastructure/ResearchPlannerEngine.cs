using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Wave 3 Research Planner — turns crash-intelligence claims into an ordered
/// experiment plan (hypothesis → experiment → expected observation).
/// Research/teaching only: deterministic sweeps/holds, no exploit payloads.
/// </summary>
public static class ResearchPlannerEngine
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    public static string PathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_research_plan.json");

    public static ResearchPlanDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<ResearchPlanDto>(File.ReadAllText(path), JsonOpts);
        }
        catch
        {
            return null;
        }
    }

    public static ResearchPlanDto? TryReadForCrash(string crashesDir, Guid crashId) =>
        TryRead(PathFor(crashesDir, crashId));

    public static ResearchPlanDto Build(
        Guid crashId,
        string project,
        RootCauseAnalysisDto? rootCause = null,
        CrashInfluenceMapDto? influence = null,
        CrashPrimitiveReportDto? primitives = null,
        HypothesisSetDto? hypotheses = null,
        SkepticReportDto? skeptic = null)
    {
        var claims = CollectClaims(rootCause, influence, primitives, hypotheses);
        if (claims.Count == 0)
        {
            return new ResearchPlanDto(
                false,
                crashId,
                project,
                "Insufficient claims for a research plan",
                "UNKNOWN",
                [],
                [],
                DateTimeOffset.UtcNow,
                "Capture debugger triage / influence links before planning experiments.",
                "no claims");
        }

        var steps = OrderSteps(claims, skeptic);
        var confidence = RollupConfidence(claims);
        var objective = BuildObjective(claims, primitives, rootCause);
        var summary =
            $"{steps.Count} ordered experiment step(s) from {claims.Count} claim(s) [{confidence}]. " +
            "Research sweeps/holds only — no exploit payloads.";

        return new ResearchPlanDto(
            true,
            crashId,
            project,
            objective,
            confidence,
            steps,
            claims,
            DateTimeOffset.UtcNow,
            summary);
    }

    public static ResearchPlanDto PersistForCrash(
        string crashesDir,
        Guid crashId,
        string project,
        RootCauseAnalysisDto? rootCause = null,
        CrashInfluenceMapDto? influence = null,
        CrashPrimitiveReportDto? primitives = null,
        HypothesisSetDto? hypotheses = null,
        SkepticReportDto? skeptic = null)
    {
        var plan = Build(crashId, project, rootCause, influence, primitives, hypotheses, skeptic);
        Write(crashesDir, plan);
        return plan;
    }

    public static string Write(string crashesDir, ResearchPlanDto plan)
    {
        Directory.CreateDirectory(crashesDir);
        var path = PathFor(crashesDir, plan.CrashId);
        File.WriteAllText(path, JsonSerializer.Serialize(plan, JsonOpts));
        return path;
    }

    private static List<ResearchClaimDto> CollectClaims(
        RootCauseAnalysisDto? rootCause,
        CrashInfluenceMapDto? influence,
        CrashPrimitiveReportDto? primitives,
        HypothesisSetDto? hypotheses)
    {
        var claims = new List<ResearchClaimDto>();

        if (rootCause is { Ok: true } && rootCause.Candidate.Category != RootCauseCategory.Unknown)
        {
            var conf = ConfidenceToPercent(rootCause.Candidate.Confidence);
            claims.Add(new ResearchClaimDto(
                "claim-root-cause",
                ResearchClaimKind.RootCause,
                $"Root cause is {rootCause.Candidate.Category} ({rootCause.Candidate.Confidence}).",
                conf,
                rootCause.Candidate.Confidence,
                conf >= 70,
                rootCause.Candidate.Evidence.Select(f => f.Name).Take(4).ToList(),
                "root_cause",
                rootCause.Candidate.InputRegion is { } region
                    && int.TryParse(region.TrimStart('+', 'p'), out var off)
                    ? off
                    : null));
        }

        if (influence?.Links is { Count: > 0 })
        {
            foreach (var link in influence.Links.Take(6))
            {
                var conf = link.Status switch
                {
                    InfluenceConfirmationStatus.Confirmed => 90,
                    InfluenceConfirmationStatus.Observed => 75,
                    InfluenceConfirmationStatus.Candidate => 55,
                    _ => 35,
                };
                claims.Add(new ResearchClaimDto(
                    $"claim-influence-{link.Id}",
                    ResearchClaimKind.InputInfluence,
                    $"Input region +{link.Region.StartOffset} influences {link.State.Kind} ({link.State.Label}).",
                    conf,
                    conf >= 80 ? "HIGH" : conf >= 60 ? "MEDIUM" : "LOW",
                    link.Status == InfluenceConfirmationStatus.Confirmed,
                    link.EvidenceRefs.Take(4).ToList(),
                    "influence",
                    link.Region.StartOffset,
                    link.HypothesisId));
            }
        }

        if (primitives?.Primitives is { Count: > 0 })
        {
            foreach (var p in primitives.Primitives.Take(6))
            {
                var conf = (int)Math.Clamp(Math.Round(p.Confidence * 100), 0, 100);
                claims.Add(new ResearchClaimDto(
                    $"claim-prim-{p.Id}",
                    ResearchClaimKind.Primitive,
                    $"Capability {p.Kind}: {p.Mechanism} ({p.State}).",
                    conf,
                    conf >= 80 ? "HIGH" : conf >= 60 ? "MEDIUM" : "LOW",
                    p.State == PrimitiveState.Confirmed,
                    p.EvidenceRefs.Take(4).ToList(),
                    "primitive",
                    p.Region?.StartOffset,
                    p.HypothesisId));
            }
        }

        if (hypotheses?.Hypotheses is { Count: > 0 })
        {
            foreach (var h in hypotheses.Hypotheses.Take(4))
            {
                claims.Add(new ResearchClaimDto(
                    $"claim-hyp-{h.Id}",
                    ResearchClaimKind.Lineage,
                    h.Statement,
                    h.ConfidencePercent,
                    h.ConfidencePercent >= 80 ? "HIGH" : h.ConfidencePercent >= 55 ? "MEDIUM" : "LOW",
                    h.Status == HypothesisStatus.Confirmed,
                    h.Evidence?.Take(4).ToList() ?? [],
                    "hypothesis",
                    h.Experiment.OffsetBytes,
                    h.Id));
            }
        }

        return claims
            .OrderByDescending(c => c.Confirmed)
            .ThenByDescending(c => c.ConfidencePercent)
            .ToList();
    }

    private static List<ResearchStepDto> OrderSteps(
        IReadOnlyList<ResearchClaimDto> claims,
        SkepticReportDto? skeptic)
    {
        var steps = new List<ResearchStepDto>();
        var order = 1;

        // Confirm unconfirmed high-value claims first (information gain).
        foreach (var claim in claims.Where(c => !c.Confirmed).Take(5))
        {
            var experiment = ExperimentFor(claim);
            steps.Add(new ResearchStepDto(
                order++,
                claim,
                experiment,
                ExpectedFor(claim, survive: true),
                "Confirm or refute before raising confidence",
                SkepticGate: false,
                claim.HypothesisId));
        }

        // Then skeptic gates for already-confirmed / high-confidence claims.
        var challenged = skeptic?.Challenges.Select(c => c.ClaimId).ToHashSet(StringComparer.Ordinal)
                         ?? new HashSet<string>(StringComparer.Ordinal);
        foreach (var claim in claims.Where(c => c.Confirmed || c.ConfidencePercent >= 70).Take(3))
        {
            if (challenged.Contains(claim.Id))
                continue;
            var experiment = FalsifyExperimentFor(claim);
            steps.Add(new ResearchStepDto(
                order++,
                claim,
                experiment,
                ExpectedFor(claim, survive: true),
                "Skeptic gate — claim confidence rises only if it survives falsification",
                SkepticGate: true,
                claim.HypothesisId));
        }

        if (steps.Count == 0 && claims.Count > 0)
        {
            var claim = claims[0];
            steps.Add(new ResearchStepDto(
                1,
                claim,
                ExperimentFor(claim),
                ExpectedFor(claim, survive: true),
                "Baseline confirmation step",
                false,
                claim.HypothesisId));
        }

        return steps;
    }

    private static HypothesisExperimentDto ExperimentFor(ResearchClaimDto claim)
    {
        var offset = claim.OffsetBytes ?? 0;
        return claim.Kind switch
        {
            ResearchClaimKind.InputInfluence or ResearchClaimKind.Primitive =>
                new HypothesisExperimentDto(
                    HypothesisExperimentKind.SweepOffset,
                    $"Sweep ±4 bytes around offset +{offset} while holding neighbors",
                    OffsetBytes: offset,
                    SweepRange: 4,
                    BudgetIterations: 3),
            ResearchClaimKind.RootCause =>
                new HypothesisExperimentDto(
                    HypothesisExperimentKind.BoundaryProbe,
                    "Probe boundary/interesting values at the attributed region",
                    OffsetBytes: offset > 0 ? offset : null,
                    BudgetIterations: 3),
            _ =>
                new HypothesisExperimentDto(
                    HypothesisExperimentKind.HoldMutator,
                    "Hold the attributed mutator and replay the crash input",
                    OffsetBytes: offset > 0 ? offset : null,
                    BudgetIterations: 2),
        };
    }

    private static HypothesisExperimentDto FalsifyExperimentFor(ResearchClaimDto claim)
    {
        var offset = claim.OffsetBytes ?? 0;
        return new HypothesisExperimentDto(
            HypothesisExperimentKind.MinimizeHold,
            claim.OffsetBytes is not null
                ? $"Neutralize bytes at +{offset} and retry — crash should stop if the claim is causal"
                : "Minimize while dropping the suspected field — claim fails if the crash persists unchanged",
            OffsetBytes: claim.OffsetBytes,
            BudgetIterations: 3);
    }

    private static string ExpectedFor(ResearchClaimDto claim, bool survive) =>
        survive
            ? $"Observation still supports: {claim.Statement}"
            : $"Observation breaks the claim (crash class/site changes or disappears).";

    private static string BuildObjective(
        IReadOnlyList<ResearchClaimDto> claims,
        CrashPrimitiveReportDto? primitives,
        RootCauseAnalysisDto? rootCause)
    {
        if (primitives is { Ok: true, Primitives.Count: > 0 })
            return $"Confirm capability '{primitives.Primitives[0].Kind}' and harden root-cause confidence";
        if (rootCause is { Ok: true })
            return $"Falsify-or-confirm root cause {rootCause.Candidate.Category}";
        return $"Rank and test top {Math.Min(3, claims.Count)} research claim(s)";
    }

    private static string RollupConfidence(IReadOnlyList<ResearchClaimDto> claims)
    {
        if (claims.Count == 0)
            return "UNKNOWN";
        var avg = claims.Average(c => c.ConfidencePercent);
        return avg >= 80 ? "HIGH" : avg >= 55 ? "MEDIUM" : "LOW";
    }

    private static int ConfidenceToPercent(string? label) => label?.ToUpperInvariant() switch
    {
        "HIGH" => 85,
        "MEDIUM" => 65,
        "LOW" => 40,
        _ => 30,
    };
}
