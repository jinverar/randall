namespace Randall.Contracts;

/// <summary>
/// ASSERT-style security-invariant language stub that maps toward Oracle rules.
/// Teaching/research DSL only — not a full parser or exploit harness.
/// </summary>
public sealed record SecurityInvariantRuleDto(
    string Id,
    string SourceLine,
    /// <summary>field-compare | presence | response-class</summary>
    string AssertKind,
    /// <summary>e.g. auth.session, response.status</summary>
    string Subject,
    /// <summary>!= | == | exists | absent</summary>
    string Operator,
    string Expected,
    /// <summary>Optional temporal gate, e.g. AFTER login</summary>
    string? Temporal,
    /// <summary>Oracle rule class: auth | state | invariant | structure</summary>
    string OracleRuleClass,
    /// <summary>Suggested OracleAuth/State/Invariant rule Type string.</summary>
    string OracleRuleType,
    /// <summary>Magician need request hint (dictionary | hunter | energy | …).</summary>
    string? NeedRequest,
    string Summary);

/// <summary>Result of compiling one or more ASSERT lines into Oracle-facing descriptors.</summary>
public sealed record SecurityInvariantCompileResult(
    bool Ok,
    IReadOnlyList<SecurityInvariantRuleDto> Rules,
    IReadOnlyList<OracleNeedDto> Needs,
    IReadOnlyList<string> Errors,
    string Summary = "");
