namespace Randall.Contracts;

/// <summary>
/// Lifecycle of a skeptic falsification challenge. A claim's confidence only rises when the
/// claim <see cref="Survived"/> a deliberate attempt to break it.
/// </summary>
public enum SkepticChallengeStatus
{
    /// <summary>Counter-experiment proposed, not yet run.</summary>
    Proposed,
    /// <summary>Counter-experiment ran and failed to break the claim — confidence rises.</summary>
    Survived,
    /// <summary>Counter-experiment broke the claim — confidence falls / claim refuted.</summary>
    Falsified,
    /// <summary>Counter-experiment ran but was ambiguous — confidence holds.</summary>
    Inconclusive,
}

/// <summary>
/// A deliberate attempt to falsify a high-confidence claim. The skeptic states the null
/// hypothesis (what would disprove the claim), proposes a deterministic counter-experiment,
/// and records whether the claim survived. Research-only — sweeps/holds, no exploit payloads.
/// </summary>
public sealed record SkepticChallengeDto(
    string Id,
    string ClaimId,
    ResearchClaimKind ClaimKind,
    string ClaimStatement,
    int ClaimConfidenceBefore,
    /// <summary>The null hypothesis — the thing that, if observed, would disprove the claim.</summary>
    string FalsificationStatement,
    /// <summary>Deterministic counter-experiment (control sweep / neutralize-and-retry).</summary>
    HypothesisExperimentDto Experiment,
    /// <summary>Observation expected if the claim is true (i.e. it survives).</summary>
    string ExpectedIfClaimTrue,
    /// <summary>Observation expected if the claim is false (i.e. it is falsified).</summary>
    string ExpectedIfClaimFalse,
    SkepticChallengeStatus Status,
    /// <summary>Confidence after the challenge — only exceeds "before" when the claim survived.</summary>
    int ClaimConfidenceAfter,
    string? Observation = null,
    int? Iteration = null,
    /// <summary>Linked hypothesis id when the challenge is tied to an existing hypothesis.</summary>
    string? HypothesisId = null,
    DateTimeOffset At = default);

/// <summary>
/// Skeptic report for one crash — falsification challenges against its high-confidence claims.
/// Persisted as <c>{guid}_skeptic.json</c>. Research/teaching only.
/// </summary>
public sealed record SkepticReportDto(
    bool Ok,
    Guid CrashId,
    string Project,
    IReadOnlyList<SkepticChallengeDto> Challenges,
    string Summary,
    DateTimeOffset At,
    string? Error = null);
