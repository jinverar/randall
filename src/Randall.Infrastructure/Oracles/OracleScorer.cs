using Randall.Contracts;

namespace Randall.Infrastructure.Oracles;

/// <summary>
/// Computes the unified Randall interestingness score (0–100) with explainable terms.
/// Formula documented in docs/ORACLES.md (Intelligence Loop section).
/// Runtime crashes dominate; unvalidated AI semantic rules score as experimental low weight.
/// </summary>
public static class OracleScorer
{
    public const int CrashBasePoints = 90;
    public const int ExperimentalViolationPoints = 8;
    public const int ExperimentalNearMissPoints = 3;
    public const int ValidatedViolationPoints = 35;
    public const int ValidatedNearMissPoints = 12;

    public static OracleScore Score(
        OracleObservation obs,
        IReadOnlyList<OracleFindingDto> findings,
        OracleSeverity maxSeverity)
    {
        var terms = new List<OracleScoreTerm>();

        // Coverage terms only when the provider actually reported new edges.
        if (obs.NewEdges > 0)
        {
            var pts = Math.Min(30, obs.NewEdges * 10);
            terms.Add(new OracleScoreTerm("new coverage", pts, $"+{obs.NewEdges} edges"));
        }

        var violations = findings.Where(f => ParseSeverity(f.Severity) == OracleSeverity.Violation).ToList();
        var nearMisses = findings.Where(f => ParseSeverity(f.Severity) == OracleSeverity.NearMiss).ToList();
        var runtimes = findings.Where(f => ParseSeverity(f.Severity) == OracleSeverity.Runtime).ToList();

        var validatedViolations = violations.Where(f => !IsExperimental(f)).ToList();
        var experimentalViolations = violations.Where(IsExperimental).ToList();
        var validatedNear = nearMisses.Where(f => !IsExperimental(f)).ToList();
        var experimentalNear = nearMisses.Where(IsExperimental).ToList();

        if (validatedViolations.Count > 0)
        {
            var pts = Math.Min(50, validatedViolations.Count * ValidatedViolationPoints);
            var detail = string.Join(", ", validatedViolations.Select(v => v.RuleId).Take(3));
            terms.Add(new OracleScoreTerm("violation", pts, detail));
        }

        if (experimentalViolations.Count > 0)
        {
            var pts = Math.Min(16, experimentalViolations.Count * ExperimentalViolationPoints);
            var detail = string.Join(", ", experimentalViolations.Select(v => v.RuleId).Take(3));
            terms.Add(new OracleScoreTerm("experimental AI", pts, detail));
        }

        if (validatedNear.Count > 0)
        {
            var pts = Math.Min(24, validatedNear.Count * ValidatedNearMissPoints);
            terms.Add(new OracleScoreTerm("near miss", pts));
        }

        if (experimentalNear.Count > 0)
        {
            var pts = Math.Min(9, experimentalNear.Count * ExperimentalNearMissPoints);
            terms.Add(new OracleScoreTerm("experimental near miss", pts,
                string.Join(", ", experimentalNear.Select(v => v.RuleId).Take(3))));
        }

        var stateAuth = findings.Where(f =>
                !IsExperimental(f) &&
                (f.RuleClass is "StateRule" or "AuthRule") &&
                ParseSeverity(f.Severity) >= OracleSeverity.NearMiss)
            .ToList();
        if (stateAuth.Count > 0)
            terms.Add(new OracleScoreTerm("state/auth", 20, stateAuth[0].RuleId));

        var semantic = findings.Where(f =>
                !IsExperimental(f) &&
                f.RuleClass is "IntegerRule" or "StructureRule" or "ResourceRule" or "DifferentialRule" or "MetamorphicRule")
            .ToList();
        if (semantic.Count > 0 && validatedViolations.Count == 0)
            terms.Add(new OracleScoreTerm("semantic", 15, semantic[0].RuleClass));

        // Runtime / crash signals dominate semantic noise.
        if (runtimes.Count > 0 || obs.Result.Crashed)
        {
            var reproBoost = Math.Min(15, runtimes.Sum(r => Math.Max(0, r.ReproductionCount - 1)) * 5);
            var crashPts = obs.Result.Crashed
                ? CrashBasePoints
                : Math.Min(40, runtimes.Count * 25);
            var pts = Math.Min(100, crashPts + reproBoost);
            var detail = obs.Result.Crashed
                ? (obs.Result.Detail ?? "crash")
                : runtimes[0].RuleId;
            terms.Add(new OracleScoreTerm(obs.Result.Crashed ? "crash" : "runtime signal", pts, detail));
        }

        if (maxSeverity == OracleSeverity.None && obs.NewEdges == 0 && findings.Count == 0)
            return OracleScore.Empty;

        var total = Math.Min(100, terms.Sum(t => t.Points));
        var summary = string.Join("; ", terms.Select(t => $"+{t.Points} {t.Label}"));
        return new OracleScore(total, terms, summary);
    }

    public static OracleScore CrashScore(string? detail, int newEdgesAtCrash)
    {
        var terms = new List<OracleScoreTerm> { new("crash", CrashBasePoints, detail) };
        if (newEdgesAtCrash > 0)
        {
            var cov = Math.Min(10, newEdgesAtCrash * 5);
            terms.Add(new OracleScoreTerm("new coverage", cov, $"+{newEdgesAtCrash} edges at crash"));
        }

        var total = Math.Min(100, terms.Sum(t => t.Points));
        return new OracleScore(total, terms, string.Join("; ", terms.Select(t => $"+{t.Points} {t.Label}")));
    }

    /// <summary>Prefer crash score when the target actually faulted.</summary>
    public static OracleScore PreferCrash(
        OracleScore? oracleScore,
        string? crashDetail,
        int newEdgesAtCrash,
        bool crashed)
    {
        if (!crashed)
            return oracleScore ?? OracleScore.Empty;
        var crash = CrashScore(crashDetail, newEdgesAtCrash);
        if (oracleScore is null || oracleScore.Total <= 0)
            return crash;
        // Keep explainable oracle terms but never let semantic FP outrank a real crash.
        if (oracleScore.Total >= crash.Total &&
            oracleScore.Terms.Any(t => t.Label is "crash" or "runtime signal"))
            return oracleScore;
        var merged = new List<OracleScoreTerm>(crash.Terms);
        foreach (var t in oracleScore.Terms.Where(t => t.Label is not ("crash" or "runtime signal")))
            merged.Add(t);
        var total = Math.Min(100, merged.Sum(t => t.Points));
        return new OracleScore(total, merged, string.Join("; ", merged.Select(t => $"+{t.Points} {t.Label}")));
    }

    public static bool IsExperimental(OracleFindingDto f) =>
        f.Experimental ||
        f.RuleId.StartsWith("ai-", StringComparison.OrdinalIgnoreCase);

    private static OracleSeverity ParseSeverity(string s) =>
        s.Trim().ToLowerInvariant() switch
        {
            "runtime" => OracleSeverity.Runtime,
            "violation" => OracleSeverity.Violation,
            "nearmiss" or "near_miss" or "near-miss" => OracleSeverity.NearMiss,
            _ => OracleSeverity.None,
        };
}
