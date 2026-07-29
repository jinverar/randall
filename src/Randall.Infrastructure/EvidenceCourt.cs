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

            // Court-confirm only with sensor evidence (not oracle scores / lineage alone).
            if (p.State == PrimitiveState.Confirmed
                && skepticOk
                && HasClaimSupportingEvidence(factList, cited, p.EvidenceRefs))
            {
                rulings.Add(new EvidenceCourtRulingDto(
                    p.Id, statement, EvidenceCourtVerdict.Confirmed,
                    "cited sensor evidence + Skeptic survived",
                    Math.Max(cited, evidenceCount), confPct));
                continue;
            }

            if (p.State == PrimitiveState.Observed
                && skepticOk
                && HasClaimSupportingEvidence(factList, cited, p.EvidenceRefs))
            {
                rulings.Add(new EvidenceCourtRulingDto(
                    p.Id, statement, EvidenceCourtVerdict.Confirmed,
                    "observed with sensor evidence + Skeptic survived (R5+)",
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
    /// Sensor EvidenceFacts + explicit lines. Synthetic <c>primitive.*</c> atoms and
    /// oracle score metadata do not satisfy the Court (avoids self-citation / score≠proof).
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
        !f.Name.StartsWith("primitive.", StringComparison.OrdinalIgnoreCase)
        && !f.Name.StartsWith("oracle.", StringComparison.OrdinalIgnoreCase)
        && !f.Name.StartsWith("lineage.", StringComparison.OrdinalIgnoreCase)
        && !string.Equals(f.Source, "oracle", StringComparison.OrdinalIgnoreCase)
        && !string.Equals(f.Source, "lineage", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Court confirmation needs claim-supporting sensor evidence.
    /// Lineage-only citations do not unlock the bag free-pass — prefer Candidate over wrong Confirmed.
    /// </summary>
    internal static bool HasClaimSupportingEvidence(
        IReadOnlyList<EvidenceFact> facts,
        int cited,
        IReadOnlyList<string>? evidenceRefs = null)
    {
        if (cited >= 1)
            return true;
        // Claim pointed at lineage / bookkeeping only → insufficient (do not borrow unrelated sensors).
        if (evidenceRefs is { Count: > 0 })
            return false;
        return facts.Any(IsClaimSupportingSensorFact);
    }

    internal static bool IsClaimSupportingSensorFact(EvidenceFact f)
    {
        if (!IsCourtAdmissibleFact(f))
            return false;
        // Lineage adjacency is context, not write/fault proof.
        if (f.Name.StartsWith("lineage.", StringComparison.OrdinalIgnoreCase))
            return false;
        var src = f.Source ?? "";
        if (src.Contains("debugger", StringComparison.OrdinalIgnoreCase)
            || src.Contains("cdb", StringComparison.OrdinalIgnoreCase)
            || src.Contains("influence", StringComparison.OrdinalIgnoreCase)
            || src.Contains("corruption", StringComparison.OrdinalIgnoreCase)
            || src.Contains("counterfactual", StringComparison.OrdinalIgnoreCase)
            || src.Contains("backward", StringComparison.OrdinalIgnoreCase)
            || src.Contains("heap", StringComparison.OrdinalIgnoreCase)
            || src.Equals("exr", StringComparison.OrdinalIgnoreCase))
            return true;

        // Named fault/write atoms are claim-supporting even when source is generic.
        return f.Name.Contains("fault", StringComparison.OrdinalIgnoreCase)
               || f.Name.Contains("write", StringComparison.OrdinalIgnoreCase)
               || f.Name.Contains("register", StringComparison.OrdinalIgnoreCase)
               || f.Name.Contains("heap", StringComparison.OrdinalIgnoreCase);
    }

    private static int CountClaimCitations(
        IReadOnlyList<string>? evidenceRefs,
        IReadOnlyList<EvidenceFact> facts)
    {
        if (evidenceRefs is not { Count: > 0 })
            return 0;

        var supportingByName = facts
            .Where(IsClaimSupportingSensorFact)
            .Select(f => f.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var n = 0;
        foreach (var r in evidenceRefs)
        {
            if (string.IsNullOrWhiteSpace(r))
                continue;
            // Lineage refs never Court-confirm a write/fault claim.
            if (r.StartsWith("lineage.", StringComparison.OrdinalIgnoreCase)
                || r.StartsWith("lineage:", StringComparison.OrdinalIgnoreCase))
                continue;
            if (supportingByName.Contains(r))
            {
                n++;
                continue;
            }

            // Allowed sensor tags only — honesty:/court:/oracle:/skeptic: are bookkeeping, not proof.
            if (IsAllowedSensorCitation(r))
                n++;
        }

        return n;
    }

    internal static bool IsAllowedSensorCitation(string r)
    {
        var colon = r.IndexOf(':');
        if (colon <= 0)
            return false;
        var prefix = r[..colon];
        return prefix.Equals("debugger", StringComparison.OrdinalIgnoreCase)
               || prefix.Equals("cdb", StringComparison.OrdinalIgnoreCase)
               || prefix.Equals("influence", StringComparison.OrdinalIgnoreCase)
               || prefix.Equals("counterfactual", StringComparison.OrdinalIgnoreCase)
               || prefix.Equals("heap", StringComparison.OrdinalIgnoreCase)
               || prefix.Equals("register", StringComparison.OrdinalIgnoreCase)
               || prefix.Equals("fault", StringComparison.OrdinalIgnoreCase)
               || prefix.Equals("backwardTrace", StringComparison.OrdinalIgnoreCase)
               || prefix.Equals("chain", StringComparison.OrdinalIgnoreCase)
               || prefix.Equals("pattern", StringComparison.OrdinalIgnoreCase)
               || prefix.Equals("corruption", StringComparison.OrdinalIgnoreCase)
               || prefix.Equals("written", StringComparison.OrdinalIgnoreCase)
               || prefix.Equals("ea", StringComparison.OrdinalIgnoreCase);
    }

    private static double ConfidenceForState(PrimitiveState state) => state switch
    {
        PrimitiveState.Confirmed => 0.9,
        PrimitiveState.Observed => 0.75,
        PrimitiveState.Candidate => 0.55,
        _ => 0.3,
    };
}
