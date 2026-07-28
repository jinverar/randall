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
        var dynamo = DynamoRioRunner.Discover().IsAvailable;
        var sancovFlag = project.Fuzz.SanitizerCoverage || requested is Sancov;

        return requested switch
        {
            DynamoRio => new Resolved(
                requested,
                dynamo ? DynamoRio : (sancovFlag ? Sancov : Semantic),
                PreferSancovIngest: sancovFlag && !dynamo,
                PreferDynamoRio: true,
                SemanticOnly: !dynamo && !sancovFlag,
                Note: dynamo
                    ? "coverage.backend=dynamorio — DynamoRIO drcov"
                    : "coverage.backend=dynamorio but DynamoRIO missing — falling back to " +
                      (sancovFlag ? "sancov ingest" : "semantic/path-novelty")),

            Sancov => new Resolved(
                requested,
                Sancov,
                PreferSancovIngest: true,
                PreferDynamoRio: dynamo,
                SemanticOnly: false,
                Note: dynamo
                    ? "coverage.backend=sancov — ingest *.sancov; DynamoRIO also available as supplement"
                    : "coverage.backend=sancov — ingest *.sancov from corpus/traces (no DynamoRIO)"),

            Semantic => new Resolved(
                requested,
                Semantic,
                PreferSancovIngest: false,
                PreferDynamoRio: false,
                SemanticOnly: true,
                Note: "coverage.backend=semantic — path-novelty / ReelDeck stages only (no BB edges)"),

            _ => new Resolved(
                Auto,
                dynamo ? DynamoRio : (sancovFlag ? Sancov : Semantic),
                PreferSancovIngest: sancovFlag,
                PreferDynamoRio: dynamo,
                SemanticOnly: !dynamo && !sancovFlag,
                Note: dynamo
                    ? "coverage.backend=auto — DynamoRIO drcov"
                    : sancovFlag
                        ? "coverage.backend=auto — sancov ingest (DynamoRIO absent)"
                        : "coverage.backend=auto — semantic/path-novelty (no BB provider)"),
        };
    }

    /// <summary>Whether fuzz iterations should attempt *.sancov ingest.</summary>
    public static bool ShouldIngestSancov(ProjectConfig project)
    {
        var r = Resolve(project);
        return r.PreferSancovIngest || project.Fuzz.SanitizerCoverage;
    }
}
