using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Wave 3 Skeptic — proposes deliberate falsification challenges against high-confidence
/// research claims. Confidence only rises when a claim <see cref="SkepticChallengeStatus.Survived"/>.
/// Research/teaching only: neutralize/sweep counter-experiments, no exploit payloads.
/// </summary>
public static class SkepticEngine
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    /// <summary>MEDIUM+ claims are challengeable — teaching falsification starts before HIGH.</summary>
    public const int MinConfidenceForChallenge = 55;

    public static string PathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_skeptic.json");

    public static SkepticReportDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<SkepticReportDto>(File.ReadAllText(path), JsonOpts);
        }
        catch
        {
            return null;
        }
    }

    public static SkepticReportDto? TryReadForCrash(string crashesDir, Guid crashId) =>
        TryRead(PathFor(crashesDir, crashId));

    public static SkepticReportDto Build(
        Guid crashId,
        string project,
        ResearchPlanDto? plan = null,
        RootCauseAnalysisDto? rootCause = null,
        CrashInfluenceMapDto? influence = null,
        CrashPrimitiveReportDto? primitives = null)
    {
        var claims = plan?.Claims?.ToList()
                     ?? ExtractFallbackClaims(rootCause, influence, primitives);
        var challenges = claims
            .Where(c => c.ConfidencePercent >= MinConfidenceForChallenge || c.Confirmed)
            .Take(5)
            .Select(BuildChallenge)
            .ToList();

        // Always challenge the strongest claim when the planner produced any — teaching stub.
        if (challenges.Count == 0 && claims.Count > 0)
            challenges.Add(BuildChallenge(claims[0]));

        if (challenges.Count == 0)
        {
            return new SkepticReportDto(
                false,
                crashId,
                project,
                [],
                "No claims ready for falsification yet.",
                DateTimeOffset.UtcNow,
                "no challengeable claims");
        }

        var summary =
            $"{challenges.Count} falsification challenge(s) proposed. " +
            "Claim confidence rises only if the counter-experiment fails to break it.";

        return new SkepticReportDto(
            true,
            crashId,
            project,
            challenges,
            summary,
            DateTimeOffset.UtcNow);
    }

    public static SkepticReportDto PersistForCrash(
        string crashesDir,
        Guid crashId,
        string project,
        ResearchPlanDto? plan = null,
        RootCauseAnalysisDto? rootCause = null,
        CrashInfluenceMapDto? influence = null,
        CrashPrimitiveReportDto? primitives = null)
    {
        var report = Build(crashId, project, plan, rootCause, influence, primitives);
        Write(crashesDir, report);
        return report;
    }

    public static string Write(string crashesDir, SkepticReportDto report)
    {
        Directory.CreateDirectory(crashesDir);
        var path = PathFor(crashesDir, report.CrashId);
        File.WriteAllText(path, JsonSerializer.Serialize(report, JsonOpts));
        return path;
    }

    /// <summary>
    /// Record an observation against a proposed challenge (Proposed → Survived/Falsified/Inconclusive).
    /// </summary>
    public static SkepticReportDto ApplyObservation(
        SkepticReportDto report,
        string challengeId,
        SkepticChallengeStatus status,
        string? observation = null,
        int? iteration = null)
    {
        if (status is not (SkepticChallengeStatus.Survived
            or SkepticChallengeStatus.Falsified
            or SkepticChallengeStatus.Inconclusive))
            throw new ArgumentOutOfRangeException(nameof(status), "Observation must settle the challenge.");

        var updated = report.Challenges.Select(c =>
        {
            if (!string.Equals(c.Id, challengeId, StringComparison.Ordinal))
                return c;
            var after = status switch
            {
                SkepticChallengeStatus.Survived => Math.Min(99, c.ClaimConfidenceBefore + 8),
                SkepticChallengeStatus.Falsified => Math.Max(10, c.ClaimConfidenceBefore - 25),
                _ => c.ClaimConfidenceBefore,
            };
            return c with
            {
                Status = status,
                ClaimConfidenceAfter = after,
                Observation = observation,
                Iteration = iteration,
                At = DateTimeOffset.UtcNow,
            };
        }).ToList();

        var survived = updated.Count(c => c.Status == SkepticChallengeStatus.Survived);
        var falsified = updated.Count(c => c.Status == SkepticChallengeStatus.Falsified);
        return report with
        {
            Challenges = updated,
            Summary = $"{survived} survived · {falsified} falsified · {updated.Count} total challenges",
            At = DateTimeOffset.UtcNow,
            Ok = true,
            Error = null,
        };
    }

    private static SkepticChallengeDto BuildChallenge(ResearchClaimDto claim)
    {
        var offset = claim.OffsetBytes;
        var experiment = new HypothesisExperimentDto(
            HypothesisExperimentKind.MinimizeHold,
            offset is not null
                ? $"Neutralize/hold-out bytes at +{offset} and replay — claim fails if fault persists unchanged"
                : "Drop the suspected mutator/field and replay — claim fails if the same fault remains",
            OffsetBytes: offset,
            BudgetIterations: 3);

        return new SkepticChallengeDto(
            $"skep-{claim.Id}",
            claim.Id,
            claim.Kind,
            claim.Statement,
            claim.ConfidencePercent,
            $"Null: the attributed evidence is coincidental — neutralizing it should not change the fault.",
            experiment,
            $"Fault class/site still matches the claim after the counter-experiment (claim survives).",
            $"Fault disappears, moves, or changes class after neutralization (claim falsified).",
            SkepticChallengeStatus.Proposed,
            claim.ConfidencePercent,
            HypothesisId: claim.HypothesisId,
            At: DateTimeOffset.UtcNow);
    }

    private static List<ResearchClaimDto> ExtractFallbackClaims(
        RootCauseAnalysisDto? rootCause,
        CrashInfluenceMapDto? influence,
        CrashPrimitiveReportDto? primitives)
    {
        // Lightweight path when planner has not run yet — reuse planner collection via a temp plan.
        var plan = ResearchPlannerEngine.Build(
            rootCause?.CrashId ?? primitives?.CrashId ?? influence?.CrashId ?? Guid.Empty,
            rootCause?.Project ?? primitives?.Project ?? influence?.Project ?? "?",
            rootCause,
            influence,
            primitives);
        return plan.Claims.ToList();
    }
}
