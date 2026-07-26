using Randall.Contracts;

namespace Randall.Infrastructure.Oracles;

/// <summary>
/// Wave 5 stub — extension point for A/B parser differential compare.
/// Today: file-harness exit/response diff via <see cref="OracleEngine"/> differential rules.
/// Future: dual-parser harness, normalized AST diff, structural equivalence (see docs/DIFFERENTIAL_ORACLE.md).
/// </summary>
public static class DifferentialOracleHook
{
    public static bool IsArmed(ProjectConfig project) =>
        project.Oracles is { Enabled: true } o && o.Differential.Count > 0;

    public static IReadOnlyList<OracleDifferentialRuleConfig> Rules(ProjectConfig project) =>
        project.Oracles?.Differential ?? [];

    /// <summary>One-line status for fuzz preflight / verbose console.</summary>
    public static string Describe(ProjectConfig project)
    {
        if (!IsArmed(project))
            return "differential oracle: not armed";
        var rules = Rules(project);
        var ids = string.Join(", ", rules.Take(4).Select(r => r.Id));
        if (rules.Count > 4)
            ids += ",…";
        return $"differential oracle: {rules.Count} rule(s) [{ids}] — file harness A/B (stub)";
    }

    /// <summary>
    /// Future hook — compare target parser output against a reference parser on the same input.
    /// Not implemented; callers should use configured <see cref="OracleDifferentialRuleConfig"/> rules today.
    /// </summary>
    public static Task<DifferentialCompareResult> CompareParsersAsync(
        ProjectConfig project,
        byte[] payload,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(new DifferentialCompareResult(
            false,
            "CompareParsersAsync is a Wave 5 stub — arm oracles.differential rules or see docs/DIFFERENTIAL_ORACLE.md"));
}

/// <summary>Future differential compare result (stub).</summary>
public sealed record DifferentialCompareResult(
    bool Ok,
    string Summary,
    string? TargetNormalized = null,
    string? ReferenceNormalized = null,
    IReadOnlyList<string>? DiffHints = null);
