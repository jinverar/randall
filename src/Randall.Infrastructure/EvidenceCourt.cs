using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Evidence Court lite — small gate when promoting claims toward CONFIRMED / R5+.
/// Reuses <see cref="EvidenceFact"/> + <see cref="SkepticEngine"/>; does not invent a parallel brain.
/// </summary>
public static class EvidenceCourt
{
    /// <summary>Aligned with <see cref="SkepticEngine.MinConfidenceForChallenge"/>.</summary>
    public const int HighConfidenceThreshold = SkepticEngine.MinConfidenceForChallenge;

    /// <summary>
    /// Promotion toward CONFIRMED / R5+ requires Skeptic survival <em>and</em>
    /// ≥1 <see cref="EvidenceFact"/> (or explicit evidence lines).
    /// </summary>
    public static bool PassesPromotionGate(
        SkepticReportDto? skeptic,
        IReadOnlyList<EvidenceFact>? facts,
        IReadOnlyList<string>? evidenceLines = null)
    {
        if (!SkepticEngine.PassesPromotionGate(skeptic))
            return false;
        return CountEvidence(facts, evidenceLines) >= 1;
    }

    public static string PromotionGateFailureReason(
        SkepticReportDto? skeptic,
        IReadOnlyList<EvidenceFact>? facts,
        IReadOnlyList<string>? evidenceLines = null)
    {
        if (!SkepticEngine.PassesPromotionGate(skeptic))
            return SkepticEngine.PromotionGateFailureReason(skeptic);
        if (CountEvidence(facts, evidenceLines) == 0)
            return "Court gate: promotion requires ≥1 EvidenceFact (or explicit evidence line)";
        return "Court gate: blocked";
    }

    public static EvidenceCourtReportDto Evaluate(
        IReadOnlyList<PrimitiveAssessmentDto> primitives,
        IReadOnlyList<EvidenceFact>? facts,
        SkepticReportDto? skeptic,
        IReadOnlyList<string>? evidenceLines = null)
    {
        var factList = facts ?? [];
        var lines = evidenceLines ?? [];
        var evidenceCount = CountEvidence(factList, lines);
        var skepticOk = SkepticEngine.PassesPromotionGate(skeptic);
        var rulings = new List<EvidenceCourtRulingDto>();

        foreach (var p in primitives)
        {
            var confPct = (int)Math.Clamp(Math.Round(p.Confidence * 100), 0, 100);
            var cited = CountClaimCitations(p.EvidenceRefs, factList);
            var statement = $"{p.Kind}: {p.Mechanism}";

            // High confidence with no evidence atoms → INVALID / demote.
            if (confPct >= HighConfidenceThreshold && evidenceCount == 0)
            {
                rulings.Add(new EvidenceCourtRulingDto(
                    p.Id, statement, EvidenceCourtVerdict.Rejected,
                    "high confidence with Evidence.Count==0 — INVALID",
                    0, confPct));
                continue;
            }

            // Promoting to Confirmed / Observed (R5+) needs a citation + Skeptic.
            var wantsPromotion = p.State is PrimitiveState.Confirmed or PrimitiveState.Observed;
            if (wantsPromotion && evidenceCount == 0 && cited == 0)
            {
                rulings.Add(new EvidenceCourtRulingDto(
                    p.Id, statement, EvidenceCourtVerdict.Rejected,
                    "promotion requires ≥1 EvidenceFact citation",
                    0, confPct));
                continue;
            }

            if (p.State == PrimitiveState.Confirmed && skepticOk && evidenceCount >= 1)
            {
                rulings.Add(new EvidenceCourtRulingDto(
                    p.Id, statement, EvidenceCourtVerdict.Confirmed,
                    "cited evidence + Skeptic survived",
                    Math.Max(cited, evidenceCount), confPct));
                continue;
            }

            if (p.State == PrimitiveState.Observed && skepticOk && evidenceCount >= 1)
            {
                rulings.Add(new EvidenceCourtRulingDto(
                    p.Id, statement, EvidenceCourtVerdict.Confirmed,
                    "observed with evidence + Skeptic survived (R5+)",
                    Math.Max(cited, evidenceCount), confPct));
                continue;
            }

            if (evidenceCount >= 1 || cited >= 1)
            {
                rulings.Add(new EvidenceCourtRulingDto(
                    p.Id, statement, EvidenceCourtVerdict.Candidate,
                    skepticOk
                        ? "evidence present — pending Confirmed state"
                        : "evidence present — pending Skeptic survival",
                    Math.Max(cited, evidenceCount), confPct));
                continue;
            }

            rulings.Add(new EvidenceCourtRulingDto(
                p.Id, statement, EvidenceCourtVerdict.Candidate,
                "insufficient evidence for promotion",
                0, confPct));
        }

        var overall = Rollup(rulings, evidenceCount, skepticOk);
        var detail = overall switch
        {
            EvidenceCourtVerdict.Confirmed =>
                $"{rulings.Count(r => r.Verdict == EvidenceCourtVerdict.Confirmed)} claim(s) Court-confirmed (evidence + Skeptic)",
            EvidenceCourtVerdict.Rejected =>
                rulings.FirstOrDefault(r => r.Verdict == EvidenceCourtVerdict.Rejected)?.Reason
                ?? "Court rejected promotion",
            _ => evidenceCount == 0
                ? "No EvidenceFacts yet — Court holds claims at candidate"
                : "Evidence present; Skeptic / confirmation still open",
        };

        return new EvidenceCourtReportDto(
            overall,
            SummaryLineFor(overall),
            rulings,
            detail);
    }

    /// <summary>Demote Rejected claims: Confirmed→Observed, Observed→Candidate; tag evidence refs.</summary>
    public static List<PrimitiveAssessmentDto> ApplyDemotions(
        IReadOnlyList<PrimitiveAssessmentDto> primitives,
        EvidenceCourtReportDto court)
    {
        var rejected = court.Rulings
            .Where(r => r.Verdict == EvidenceCourtVerdict.Rejected)
            .Select(r => r.ClaimId)
            .ToHashSet(StringComparer.Ordinal);

        if (rejected.Count == 0)
            return primitives.ToList();

        return primitives.Select(p =>
        {
            if (!rejected.Contains(p.Id))
                return p;

            var next = p.State switch
            {
                PrimitiveState.Confirmed => PrimitiveState.Observed,
                PrimitiveState.Observed => PrimitiveState.Candidate,
                _ => p.State,
            };
            if (next == p.State && p.Confidence < HighConfidenceThreshold / 100.0)
                return p;

            return p with
            {
                State = next,
                Confidence = next == p.State
                    ? Math.Min(p.Confidence, (HighConfidenceThreshold - 1) / 100.0)
                    : ConfidenceForState(next),
                Mechanism = p.Mechanism.Contains("Court:", StringComparison.Ordinal)
                    ? p.Mechanism
                    : p.Mechanism + " (Court: rejected — no evidence)",
                EvidenceRefs = p.EvidenceRefs.Append("court:rejected").Distinct().Take(8).ToList(),
            };
        }).ToList();
    }

    public static string SummaryLineFor(EvidenceCourtVerdict v) => v switch
    {
        EvidenceCourtVerdict.Confirmed => "Court: confirmed",
        EvidenceCourtVerdict.Rejected => "Court: rejected",
        _ => "Court: candidate",
    };

    private static EvidenceCourtVerdict Rollup(
        IReadOnlyList<EvidenceCourtRulingDto> rulings,
        int evidenceCount,
        bool skepticOk)
    {
        if (rulings.Count == 0)
        {
            if (evidenceCount == 0)
                return EvidenceCourtVerdict.Candidate;
            return skepticOk ? EvidenceCourtVerdict.Confirmed : EvidenceCourtVerdict.Candidate;
        }

        if (rulings.Any(r => r.Verdict == EvidenceCourtVerdict.Confirmed))
            return EvidenceCourtVerdict.Confirmed;
        if (rulings.Any(r => r.Verdict == EvidenceCourtVerdict.Rejected))
            return EvidenceCourtVerdict.Rejected;
        return EvidenceCourtVerdict.Candidate;
    }

    /// <summary>
    /// Sensor EvidenceFacts + explicit lines. Synthetic <c>primitive.*</c> atoms from
    /// <see cref="PrimitiveEngine"/> do not satisfy the Court (avoids self-citation).
    /// </summary>
    private static int CountEvidence(
        IReadOnlyList<EvidenceFact>? facts,
        IReadOnlyList<string>? evidenceLines)
    {
        var n = facts?.Count(IsCourtAdmissibleFact) ?? 0;
        if (evidenceLines is { Count: > 0 })
            n += evidenceLines.Count(l => !string.IsNullOrWhiteSpace(l));
        return n;
    }

    internal static bool IsCourtAdmissibleFact(EvidenceFact f) =>
        !f.Name.StartsWith("primitive.", StringComparison.OrdinalIgnoreCase);

    private static int CountClaimCitations(
        IReadOnlyList<string>? evidenceRefs,
        IReadOnlyList<EvidenceFact> facts)
    {
        if (evidenceRefs is not { Count: > 0 })
            return 0;

        var factNames = facts
            .Select(f => f.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var n = 0;
        foreach (var r in evidenceRefs)
        {
            if (string.IsNullOrWhiteSpace(r))
                continue;
            // Explicit EvidenceFact name match, or a sensor tag (debugger:/influence:/…).
            if (factNames.Contains(r) || r.Contains(':', StringComparison.Ordinal))
                n++;
        }

        return n;
    }

    private static double ConfidenceForState(PrimitiveState state) => state switch
    {
        PrimitiveState.Confirmed => 0.9,
        PrimitiveState.Observed => 0.75,
        PrimitiveState.Candidate => 0.55,
        _ => 0.3,
    };
}
