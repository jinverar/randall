namespace Randall.Contracts;

/// <summary>
/// Evidence Court lite — gate for promoting claims toward CONFIRMED / R5+.
/// Reuses <see cref="EvidenceFact"/> + Skeptic; not a parallel investigation brain.
/// </summary>
public enum EvidenceCourtVerdict
{
    /// <summary>High-confidence with no evidence, or failed promotion gate — demoted / INVALID.</summary>
    Rejected,
    /// <summary>Evidence present (or claim pending) — not yet Court-confirmed for R5+.</summary>
    Candidate,
    /// <summary>Cited evidence + Skeptic survival — eligible for CONFIRMED / R5+.</summary>
    Confirmed,
}

/// <summary>One claim's Court ruling.</summary>
public sealed record EvidenceCourtRulingDto(
    string ClaimId,
    string ClaimStatement,
    EvidenceCourtVerdict Verdict,
    string Reason,
    int EvidenceCount,
    int ConfidencePercent);

/// <summary>
/// Court rollup for a crash. Surface briefly as
/// <c>Court: rejected</c> / <c>Court: candidate</c> / <c>Court: confirmed</c>.
/// </summary>
public sealed record EvidenceCourtReportDto(
    EvidenceCourtVerdict Overall,
    /// <summary>Brief operator line, e.g. <c>Court: confirmed</c>.</summary>
    string SummaryLine,
    IReadOnlyList<EvidenceCourtRulingDto> Rulings,
    string? Detail = null);
