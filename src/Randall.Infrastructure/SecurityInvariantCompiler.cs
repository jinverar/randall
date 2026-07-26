using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Table-driven stub compiler for ASSERT-style security-invariant language lines.
/// Maps teaching DSL into Oracle rule descriptors + Magician <see cref="OracleNeedDto"/> hints.
/// Not a full parser — deliberately small and documented for research use.
/// </summary>
public static partial class SecurityInvariantCompiler
{
    // ASSERT <subject> <op> <expected> [AFTER <event>]
    // Examples:
    //   ASSERT auth.session != null AFTER login
    //   ASSERT response.status != 500
    //   ASSERT auth.role == admin AFTER login
    private static readonly Regex AssertLine = AssertLineRegex();

    [GeneratedRegex(
        @"^\s*ASSERT\s+(?<subject>[\w.]+)\s+(?<op>!=|==|exists|absent)\s*(?<expected>\S+)?(?:\s+AFTER\s+(?<temporal>\S+))?\s*$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AssertLineRegex();

    public static SecurityInvariantCompileResult Compile(string source)
    {
        var lines = (source ?? "")
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return CompileLines(lines);
    }

    public static SecurityInvariantCompileResult CompileLines(IEnumerable<string> lines)
    {
        var rules = new List<SecurityInvariantRuleDto>();
        var needs = new List<OracleNeedDto>();
        var errors = new List<string>();
        var n = 0;

        foreach (var raw in lines)
        {
            n++;
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith("//"))
                continue;

            var rule = TryParseLine(line, n);
            if (rule is null)
            {
                errors.Add($"line {n}: unrecognized ASSERT syntax: {line}");
                continue;
            }

            rules.Add(rule);
            if (!string.IsNullOrWhiteSpace(rule.NeedRequest))
            {
                needs.Add(new OracleNeedDto(
                    rule.NeedRequest!,
                    rule.Summary,
                    rule.OracleRuleClass,
                    rule.Id,
                    "violation"));
            }
        }

        var ok = rules.Count > 0 && errors.Count == 0;
        var summary = rules.Count == 0
            ? (errors.Count == 0
                ? "No ASSERT lines provided."
                : $"{errors.Count} parse error(s); no rules emitted.")
            : $"Compiled {rules.Count} invariant rule(s) → {needs.Count} OracleNeed hint(s)" +
              (errors.Count == 0 ? "." : $" ({errors.Count} error(s)).");

        // Soft-ok when we got at least one rule even if some lines failed.
        if (rules.Count > 0)
            ok = true;

        return new SecurityInvariantCompileResult(ok, rules, needs, errors, summary);
    }

    public static SecurityInvariantRuleDto? TryParseLine(string line, int index = 1)
    {
        if (string.IsNullOrWhiteSpace(line))
            return null;

        var m = AssertLine.Match(line.Trim());
        if (!m.Success)
            return null;

        var subject = m.Groups["subject"].Value;
        var op = m.Groups["op"].Value.ToLowerInvariant();
        var expected = m.Groups["expected"].Success
            ? m.Groups["expected"].Value
            : "";
        var temporal = m.Groups["temporal"].Success
            ? m.Groups["temporal"].Value
            : null;

        if (op is "exists" or "absent")
            expected = op;

        var mapped = MapToOracle(subject, op, expected, temporal);
        var id = $"sil-{index:D3}-{SanitizeId(subject)}";

        return new SecurityInvariantRuleDto(
            id,
            line.Trim(),
            mapped.AssertKind,
            subject,
            op,
            expected,
            temporal,
            mapped.OracleRuleClass,
            mapped.OracleRuleType,
            mapped.NeedRequest,
            mapped.Summary);
    }

    private static (string AssertKind, string OracleRuleClass, string OracleRuleType, string? NeedRequest, string Summary)
        MapToOracle(string subject, string op, string expected, string? temporal)
    {
        var subj = subject.ToLowerInvariant();
        var hasAfter = !string.IsNullOrWhiteSpace(temporal);

        // auth.* → auth / state oracle packs
        if (subj.StartsWith("auth.", StringComparison.Ordinal))
        {
            var field = subj["auth.".Length..];
            if (op == "!=" && expected.Equals("null", StringComparison.OrdinalIgnoreCase) && hasAfter)
            {
                return (
                    "field-compare",
                    "auth",
                    "requireAuth",
                    "dictionary",
                    $"Require auth.{field} present after '{temporal}' (session established).");
            }

            if (op == "==" && hasAfter)
            {
                return (
                    "field-compare",
                    "auth",
                    "forbidUntil",
                    "hunter",
                    $"Expect auth.{field} == {expected} after '{temporal}' (role/claim teaching check).");
            }

            return (
                "field-compare",
                "auth",
                "requireAuth",
                "dictionary",
                $"Auth field '{field}' {op} {expected}" +
                (hasAfter ? $" after '{temporal}'" : "") + ".");
        }

        // response.* → invariant / structure
        if (subj.StartsWith("response.", StringComparison.Ordinal))
        {
            var field = subj["response.".Length..];
            if (field is "status" or "code" && op == "!=" )
            {
                return (
                    "response-class",
                    "invariant",
                    "forbidResponseClass",
                    "energy",
                    $"Forbid response {field} == {expected} (teaching invariant).");
            }

            if (op == "exists" || (op == "!=" && expected.Equals("null", StringComparison.OrdinalIgnoreCase)))
            {
                return (
                    "presence",
                    "invariant",
                    "expectSubstring",
                    "dictionary",
                    $"Expect response.{field} present.");
            }

            return (
                "field-compare",
                "invariant",
                "expectSubstring",
                "dictionary",
                $"Response field '{field}' {op} {expected}.");
        }

        // state.* → state machine
        if (subj.StartsWith("state.", StringComparison.Ordinal) || hasAfter)
        {
            return (
                "field-compare",
                "state",
                "commandRequiresPrior",
                "hunter",
                $"State/order check on '{subject}' {op} {expected}" +
                (hasAfter ? $" after '{temporal}'" : "") + ".");
        }

        // Default → generic invariant
        return (
            op is "exists" or "absent" ? "presence" : "field-compare",
            "invariant",
            op == "absent" || (op == "==" && expected.Equals("null", StringComparison.OrdinalIgnoreCase))
                ? "forbidSubstring"
                : "expectSubstring",
            "dictionary",
            $"Invariant '{subject}' {op} {expected}" +
            (hasAfter ? $" after '{temporal}'" : "") + ".");
    }

    private static string SanitizeId(string subject)
    {
        var chars = subject.Select(c => char.IsLetterOrDigit(c) ? c : '-').ToArray();
        return new string(chars).Trim('-').ToLowerInvariant();
    }
}
