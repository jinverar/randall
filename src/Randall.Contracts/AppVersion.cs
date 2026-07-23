namespace Randall.Contracts;

/// <summary>Single source of truth for product version strings.</summary>
public static class AppVersion
{
    public const string ProductName = "Randfuzz by Randall";
    /// <summary>SemVer-ish product version (may include -alpha / -rc suffix).</summary>
    public const string Version = "0.17.0-alpha";
    public const string Status = "phase17-updates";
    public const string Display = ProductName + " " + Version;

    public static string InformalLine =>
        $"{Display} ({Status} — secure update check)";
}
