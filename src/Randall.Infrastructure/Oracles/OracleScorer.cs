using Randall.Contracts;

namespace Randall.Infrastructure.Oracles;

/// <summary>
/// Computes the unified Randall interestingness score (0–100) with explainable terms.
/// Formula documented in docs/ORACLES.md (Intelligence Loop section).
/// </summary>
public static class OracleScorer
{
    public static OracleScore Score(
        OracleObservation obs,
        IReadOnlyList<OracleFindingDto> findings,
        OracleSeverity maxSeverity)
    {
        var terms = new List<OracleScoreTerm>();

        if (obs.NewEdges > 0)
        {
            var pts = Math.Min(30, obs.NewEdges * 10);
            terms.Add(new OracleScoreTerm("new coverage", pts, $"+{obs.NewEdges} edges"));
        }

        var violations = findings.Where(f => ParseSeverity(f.Severity) == OracleSeverity.Violation).ToList();
        var nearMisses = findings.Where(f => ParseSeverity(f.Severity) == OracleSeverity.NearMiss).ToList();
        var runtimes = findings.Where(f => ParseSeverity(f.Severity) == OracleSeverity.Runtime).ToList();

        if (violations.Count > 0)
        {
            var pts = Math.Min(50, violations.Count * 35);
            var detail = string.Join(", ", violations.Select(v => v.RuleId).Take(3));
            terms.Add(new OracleScoreTerm("violation", pts, detail));
        }

        if (nearMisses.Count > 0)
        {
            var pts = Math.Min(24, nearMisses.Count * 12);
            terms.Add(new OracleScoreTerm("near miss", pts));
        }

        var stateAuth = findings.Where(f =>
                (f.RuleClass is "StateRule" or "AuthRule") &&
                ParseSeverity(f.Severity) >= OracleSeverity.NearMiss)
            .ToList();
        if (stateAuth.Count > 0)
            terms.Add(new OracleScoreTerm("state/auth", 20, stateAuth[0].RuleId));

        var semantic = findings.Where(f =>
                f.RuleClass is "IntegerRule" or "StructureRule" or "ResourceRule" or "DifferentialRule" or "MetamorphicRule")
            .ToList();
        if (semantic.Count > 0 && violations.Count == 0)
            terms.Add(new OracleScoreTerm("semantic", 15, semantic[0].RuleClass));

        if (runtimes.Count > 0)
        {
            var pts = Math.Min(40, runtimes.Count * 25);
            terms.Add(new OracleScoreTerm("runtime signal", pts, runtimes[0].RuleId));
        }

        if (maxSeverity == OracleSeverity.None && obs.NewEdges == 0 && findings.Count == 0)
            return OracleScore.Empty;

        var total = Math.Min(100, terms.Sum(t => t.Points));
        var summary = string.Join("; ", terms.Select(t => $"+{t.Points} {t.Label}"));
        return new OracleScore(total, terms, summary);
    }

    public static OracleScore CrashScore(string? detail, int newEdgesAtCrash)
    {
        var terms = new List<OracleScoreTerm> { new("crash", 80, detail) };
        if (newEdgesAtCrash > 0)
        {
            var cov = Math.Min(20, newEdgesAtCrash * 10);
            terms.Add(new OracleScoreTerm("new coverage", cov, $"+{newEdgesAtCrash} edges at crash"));
        }

        var total = Math.Min(100, terms.Sum(t => t.Points));
        return new OracleScore(total, terms, string.Join("; ", terms.Select(t => $"+{t.Points} {t.Label}")));
    }

    private static OracleSeverity ParseSeverity(string s) =>
        s.Trim().ToLowerInvariant() switch
        {
            "runtime" => OracleSeverity.Runtime,
            "violation" => OracleSeverity.Violation,
            "nearmiss" or "near_miss" or "near-miss" => OracleSeverity.NearMiss,
            _ => OracleSeverity.None,
        };
}
