namespace Randall.Contracts;

/// <summary>
/// Why-haven't-I-found-it barrier taxonomy. Teaching/diagnosis only — never exploit automation.
/// </summary>
public enum BarrierKind
{
    /// <summary>No scored gray doors / frontier empty or mode=empty.</summary>
    EmptyFrontier,
    /// <summary>Mutator credit scores flat — no productive mutator differentiation.</summary>
    FlatMutatorCredit,
    /// <summary>Coverage / corpus novelty stagnant across recent layers or edges.</summary>
    StagnantCoverage,
    /// <summary>Oracle findings absent or only soft near-misses after many iterations.</summary>
    QuietOracle,
    /// <summary>Dictionary tokens missing or very thin for the target class.</summary>
    ThinDictionary,
    /// <summary>Brain inactive / no stalk signals to steer the hunt.</summary>
    QuietBrain,
}

/// <summary>One diagnosed campaign barrier with teaching-only suggested actions.</summary>
public sealed record BarrierItemDto(
    string Id,
    BarrierKind Kind,
    /// <summary>high | medium | low</summary>
    string Severity,
    string Diagnosis,
    /// <summary>Teaching/research actions only — never payloads, ROP, or shellcode.</summary>
    IReadOnlyList<string> SuggestedActions);

/// <summary>
/// "Why haven't I found it?" campaign barrier rollup.
/// Persisted at <c>data/stalk/&lt;project&gt;/barrier_diagnosis.json</c>
/// (fallback: <c>data/crashes/&lt;project&gt;/barrier_diagnosis.json</c>).
/// </summary>
public sealed record BarrierReportDto(
    bool Ok,
    string Project,
    DateTimeOffset At,
    string Summary,
    IReadOnlyList<BarrierItemDto> Barriers,
    /// <summary>Artifact paths / heuristic labels that contributed (soft-fail when missing).</summary>
    IReadOnlyList<string> SignalsUsed,
    string? Error = null);
