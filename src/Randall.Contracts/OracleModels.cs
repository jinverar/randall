namespace Randall.Contracts;

/// <summary>
/// Hybrid semantic oracle config — supplements coverage for logic / auth / state /
/// structure bugs (especially valuable on memory-safe targets). See docs/ORACLES.md.
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

    /// <summary>Authentication / authorization semantic rules.</summary>
    public List<OracleAuthRuleConfig> Auth { get; set; } = [];

    /// <summary>Protocol / session state-machine rules.</summary>
    public List<OracleStateRuleConfig> State { get; set; } = [];

    /// <summary>Semantic integer / length-field rules (not just crashy overflows).</summary>
    public List<OracleIntegerRuleConfig> Integer { get; set; } = [];

    /// <summary>Incorrect assumptions about structure (headers, magic, sizes).</summary>
    public List<OracleStructureRuleConfig> Structure { get; set; } = [];

    /// <summary>Resource exhaustion signals (response size, payload size).</summary>
    public List<OracleResourceRuleConfig> Resource { get; set; } = [];

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

/// <summary>AuthN/AuthZ semantic rules for memory-safe / logic-bug hunting.</summary>
public sealed class OracleAuthRuleConfig
{
    public string Id { get; set; } = "";
    /// <summary>
    /// forbidUntil — forbid <see cref="ForbidResponse"/> until <see cref="UntilResponse"/> has been observed.
    /// requireAuth — whenCommand requires prior UntilResponse (authenticated marker).
    /// </summary>
    public string Type { get; set; } = "forbidUntil";
    public string? ForbidResponse { get; set; }
    /// <summary>Response substring that marks authentication / bind success.</summary>
    public string? UntilResponse { get; set; }
    public string? WhenCommand { get; set; }
    public string Severity { get; set; } = "violation";
}

/// <summary>State-machine / session-order rules.</summary>
public sealed class OracleStateRuleConfig
{
    public string Id { get; set; } = "";
    /// <summary>
    /// commandRequiresPrior — forCommand requires a prior priorCommand (optionally with priorResponse).
    /// forbidResponseInState — when session has not seen untilResponse, forbid forbidResponse (alias of auth).
    /// </summary>
    public string Type { get; set; } = "commandRequiresPrior";
    public string? ForCommand { get; set; }
    public string? PriorCommand { get; set; }
    public string? PriorResponse { get; set; }
    public string? ForbidResponse { get; set; }
    public string? UntilResponse { get; set; }
    public string Severity { get; set; } = "violation";
}

/// <summary>Semantic integer / length inconsistencies (meaningful overflows, not just crashes).</summary>
public sealed class OracleIntegerRuleConfig
{
    public string Id { get; set; } = "";
    /// <summary>
    /// lengthPrefix — interpret bytes at offset as length; flag if claimed length ≠ body / overflows.
    /// claimedExceedsPayload — length field larger than remaining bytes.
    /// </summary>
    public string Type { get; set; } = "lengthPrefix";
    public int Offset { get; set; }
    /// <summary>1, 2, or 4</summary>
    public int Width { get; set; } = 4;
    /// <summary>le | be</summary>
    public string Endian { get; set; } = "le";
    /// <summary>rest — length covers bytes after the length field; self — length includes header.</summary>
    public string Covers { get; set; } = "rest";
    /// <summary>Optional max plausible length (semantic ceiling).</summary>
    public int? MaxPlausible { get; set; }
    public string? WhenCommand { get; set; }
    public string Severity { get; set; } = "violation";
}

/// <summary>Incorrect assumptions about framing / magic / minimum structure.</summary>
public sealed class OracleStructureRuleConfig
{
    public string Id { get; set; } = "";
    /// <summary>minSize | maxSize | requirePrefix | requireMagicHex</summary>
    public string Type { get; set; } = "minSize";
    public int? Bytes { get; set; }
    public string? Prefix { get; set; }
    public string? Hex { get; set; }
    public string? WhenCommand { get; set; }
    /// <summary>
    /// If true, structure failures on the *input* are near-misses (mutator noise).
    /// If false, treat as violations (useful when the target accepted a malformed PDU).
    /// </summary>
    public bool OnlyWhenAccepted { get; set; } = true;
    public string Severity { get; set; } = "nearMiss";
}

/// <summary>Resource exhaustion / abuse signals without requiring a crash.</summary>
public sealed class OracleResourceRuleConfig
{
    public string Id { get; set; } = "";
    /// <summary>maxResponseBytes | maxPayloadBytes | responseToPayloadRatio</summary>
    public string Type { get; set; } = "maxResponseBytes";
    public int? MaxBytes { get; set; }
    /// <summary>For responseToPayloadRatio — flag when response_len &gt; ratio * payload_len.</summary>
    public double? MaxRatio { get; set; }
    public string? WhenCommand { get; set; }
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
