using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Resolves <c>coverage.backend</c> / <c>fuzz.coverageBackend</c> into an effective edge source.
/// Tokens: auto | sancov | dynamorio | semantic.
/// </summary>
public static class CoverageBackendResolver
{
    public const string Auto = "auto";
    public const string Sancov = "sancov";
    public const string DynamoRio = "dynamorio";
    public const string Semantic = "semantic";

    public sealed record Resolved(
        string Requested,
        string Effective,
        bool PreferSancovIngest,
        bool PreferDynamoRio,
        bool SemanticOnly,
        string Note);

    public static string RequestedToken(ProjectConfig project)
    {
        var nested = (project.Coverage?.Backend ?? "").Trim();
        if (!string.IsNullOrWhiteSpace(nested))
            return nested.ToLowerInvariant();
        var alias = (project.Fuzz.CoverageBackend ?? "").Trim();
        if (!string.IsNullOrWhiteSpace(alias))
            return alias.ToLowerInvariant();
        return Auto;
    }

    public static Resolved Resolve(ProjectConfig project)
    {
        var requested = RequestedToken(project);
        var dr = DynamoRioRunner.Diagnose();
        var dynamo = dr.IsAvailable;
        var sancovFlag = project.Fuzz.SanitizerCoverage || requested is Sancov;
        var noBbReason = dr.State == "incomplete"
            ? "drrun missing from DynamoRIO home — path/session novelty only (not basic-block edges)"
            : "drrun not found — path/session novelty only (not basic-block edges)";

        return requested switch
        {
            DynamoRio => new Resolved(
                requested,
                dynamo ? DynamoRio : (sancovFlag ? Sancov : Semantic),
                PreferSancovIngest: sancovFlag && !dynamo,
                PreferDynamoRio: true,
                SemanticOnly: !dynamo && !sancovFlag,
                Note: dynamo
                    ? $"coverage.backend=dynamorio — DynamoRIO drcov ({dr.DrrunPath})"
                    : "coverage.backend=dynamorio but drrun not found — falling back to " +
                      (sancovFlag ? "sancov ingest" : "path/session novelty")),

            Sancov => new Resolved(
                requested,
                Sancov,
                PreferSancovIngest: true,
                PreferDynamoRio: dynamo,
                SemanticOnly: false,
                Note: dynamo
                    ? "coverage.backend=sancov — ingest *.sancov; DynamoRIO also available as supplement"
                    : "coverage.backend=sancov — ingest *.sancov from corpus/traces (drrun not found)"),

            Semantic => new Resolved(
                requested,
                Semantic,
                PreferSancovIngest: false,
                PreferDynamoRio: false,
                SemanticOnly: true,
                Note: "coverage.backend=semantic — path/session novelty only (basic-block edges off by choice)"),

            _ => new Resolved(
                Auto,
                dynamo ? DynamoRio : (sancovFlag ? Sancov : Semantic),
                PreferSancovIngest: sancovFlag,
                PreferDynamoRio: dynamo,
                SemanticOnly: !dynamo && !sancovFlag,
                Note: dynamo
                    ? $"coverage.backend=auto — DynamoRIO drcov ({dr.DrrunPath})"
                    : sancovFlag
                        ? "coverage.backend=auto — sancov ingest (drrun not found)"
                        : $"coverage.backend=auto — {noBbReason}"),
        };
    }

    /// <summary>Whether fuzz iterations should attempt *.sancov ingest.</summary>
    public static bool ShouldIngestSancov(ProjectConfig project)
    {
        var r = Resolve(project);
        return r.PreferSancovIngest || project.Fuzz.SanitizerCoverage;
    }
}
