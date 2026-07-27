namespace Randall.Contracts;

/// <summary>
/// Randall analysis-engine identity stamped into investigation JSON and /api/health.
/// Optional on legacy artifacts (absent → treat as older than running build).
/// </summary>
public sealed record RandallBuildIdentityDto(
    string Version,
    string? InformationalVersion,
    string? GitCommit,
    DateTimeOffset? BuildTime,
    string AnalyzerLabel,
    string SchemaLabel);
