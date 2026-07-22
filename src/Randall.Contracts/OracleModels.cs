namespace Randall.Contracts;

/// <summary>
/// Hybrid semantic oracle config — supplements coverage, does not replace it.
/// See docs/ORACLES.md.
/// </summary>
public sealed class OracleConfig
{
    /// <summary>Master switch. When false, oracle stack is skipped.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Keep inputs that trigger confirmed oracle violations in the corpus.</summary>
    public bool RetainOnViolation { get; set; } = true;

    /// <summary>Keep near-miss inputs (soft semantic signal) in the corpus with lower energy.</summary>
    public bool RetainOnNearMiss { get; set; } = true;

    /// <summary>Write oracle_findings.jsonl under the crashes/oracle dir.</summary>
    public bool PersistFindings { get; set; } = true;

    /// <summary>Treat invariant mismatches as violations (default) or only as near-misses.</summary>
    public string InvariantSeverity { get; set; } = "violation"; // violation | nearMiss

    /// <summary>Single-execution invariants (expect / forbid / max length / exit code).</summary>
    public List<OracleInvariantRuleConfig> Invariants { get; set; } = [];

    /// <summary>Compare this target against a reference implementation (file harness v1).</summary>
    public List<OracleDifferentialRuleConfig> Differential { get; set; } = [];

    /// <summary>Transform input, re-execute, verify relationships.</summary>
    public List<OracleMetamorphicRuleConfig> Metamorphic { get; set; } = [];

    /// <summary>
    /// When true, promote session <c>expectResponse</c> mismatches into the oracle stack
    /// (interesting / violation) instead of Detail-only.
    /// </summary>
    public bool PromoteExpectResponse { get; set; } = true;

    /// <summary>When true, RPP post_receive abort maps to an invariant violation.</summary>
    public bool PromotePostReceiveAbort { get; set; } = true;
}

public sealed class OracleInvariantRuleConfig
{
    public string Id { get; set; } = "";
    /// <summary>expectSubstring | forbidSubstring | maxResponseBytes | exitCodeZero | exitCodeNonZero</summary>
    public string Type { get; set; } = "expectSubstring";
    public string? Pattern { get; set; }
    public int? MaxBytes { get; set; }
    /// <summary>Optional: only apply when command name contains this (case-insensitive).</summary>
    public string? WhenCommand { get; set; }
    /// <summary>violation | nearMiss</summary>
    public string Severity { get; set; } = "violation";
}

public sealed class OracleDifferentialRuleConfig
{
    public string Id { get; set; } = "";
    /// <summary>fileExit | fileResponse — reference must be a file harness taking @@ / {file}.</summary>
    public string Type { get; set; } = "fileExit";
    public string ReferenceExecutable { get; set; } = "";
    public List<string> ReferenceArgs { get; set; } = ["@@"];
    public int TimeoutMs { get; set; } = 2000;
}

public sealed class OracleMetamorphicRuleConfig
{
    public string Id { get; set; } = "";
    /// <summary>
    /// whitespaceInsensitive — strip runs of whitespace in text, re-exec, compare normalized response class.
    /// duplicateIdempotent — send payload twice on one TCP connection; second response class should match first (lab).
    /// </summary>
    public string Type { get; set; } = "whitespaceInsensitive";
    /// <summary>violation | nearMiss</summary>
    public string Severity { get; set; } = "nearMiss";
}

public sealed record OracleFindingDto(
    string Id,
    string Project,
    string RuleId,
    string RuleClass,
    string Severity,
    double Confidence,
    string InputHash,
    string? Command,
    string? Mutator,
    int Iteration,
    string ExpectedRelation,
    string ActualRelation,
    string? NormalizedObservation,
    string? TransformationChain,
    string? CoverageSignature,
    int ReproductionCount,
    DateTimeOffset At);
