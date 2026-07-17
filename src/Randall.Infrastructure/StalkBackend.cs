namespace Randall.Infrastructure;

/// <summary>
/// Coverage / trace backend identifiers. External backends (e.g. DynamoRIO drcov) are pluggable;
/// Randall native stalking will use <see cref="Native"/> when implemented (Phase 16+).
/// </summary>
public static class StalkBackend
{
    public const string None = "none";
    public const string External = "external";
    public const string Native = "native";

    public static string Resolve(bool coverageGuided, bool externalAvailable) =>
        coverageGuided && externalAvailable ? External : None;

    public const string ExternalNote =
        "Optional external instrumentation (DynamoRIO drcov). Will be replaceable by Randall native stalk.";

    public const string NativeNote =
        "Reserved for Randall-native basic-block stalk (no third-party runtime required).";
}
