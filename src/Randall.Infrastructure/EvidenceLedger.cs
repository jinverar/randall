using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Evidence Ledger lite — display taxonomy over existing <see cref="EvidenceFact"/> atoms.
/// Not a parallel investigation brain; maps ObservationType → Kind for UI claim rows.
/// </summary>
public enum EvidenceKind
{
    /// <summary>Read directly from a sensor transcript.</summary>
    Observed,
    /// <summary>Deterministic join across sensors (attribution, address class).</summary>
    Derived,
    /// <summary>Weaker inferred join (low confidence).</summary>
    Heuristic,
    /// <summary>Ranked / untested theory.</summary>
    Hypothesis,
    /// <summary>Confirmed by deterministic replay / experiment.</summary>
    Confirmed,
}

/// <summary>One ledger row for Investigation / Exploit Research claim lists.</summary>
public sealed record EvidenceLedgerClaim(
    EvidenceKind Kind,
    string Name,
    string? Value,
    string Source,
    double Confidence,
    string? SourceArtifact = null);

/// <summary>Builds ledger claim rows from EvidenceFact lists.</summary>
public static class EvidenceLedger
{
    public const double HeuristicConfidenceCeiling = 0.55;

    public static EvidenceKind KindFor(EvidenceFact fact) => fact.ObservationType switch
    {
        EvidenceObservationType.Observed => EvidenceKind.Observed,
        EvidenceObservationType.ExperimentallyConfirmed => EvidenceKind.Confirmed,
        EvidenceObservationType.Hypothesized => EvidenceKind.Hypothesis,
        EvidenceObservationType.Inferred =>
            fact.Confidence < HeuristicConfidenceCeiling ? EvidenceKind.Heuristic : EvidenceKind.Derived,
        _ => EvidenceKind.Heuristic,
    };

    public static EvidenceKind KindFor(EvidenceObservationType observationType, double confidence = 1.0) =>
        KindFor(new EvidenceFact(
            "_", null, "_", null, observationType, confidence, DateTimeOffset.UnixEpoch));

    public static IReadOnlyList<EvidenceLedgerClaim> FromFacts(IEnumerable<EvidenceFact>? facts)
    {
        if (facts is null)
            return [];

        return facts
            .Where(f => !string.IsNullOrWhiteSpace(f.Name))
            .Select(f => new EvidenceLedgerClaim(
                KindFor(f),
                f.Name,
                f.Value,
                f.Source,
                f.Confidence,
                f.SourceArtifact))
            .ToList();
    }

    public static string KindLabel(EvidenceKind kind) => kind switch
    {
        EvidenceKind.Observed => "Observed",
        EvidenceKind.Derived => "Derived",
        EvidenceKind.Heuristic => "Heuristic",
        EvidenceKind.Hypothesis => "Hypothesis",
        EvidenceKind.Confirmed => "Confirmed",
        _ => "Heuristic",
    };
}
