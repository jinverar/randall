using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Resolves the fuzzing platform for doctor / UI. The host OS is auto-detected; a user may
/// explicitly request <c>windows</c> or <c>linux</c> (e.g. to preview the other platform's
/// options). Any non-Windows host (Linux, macOS/BSD) maps to the <c>linux</c> Unix-tool scope.
/// </summary>
public static class PlatformResolver
{
    /// <summary>The real host OS, as a <see cref="PlatformScope"/> value.</summary>
    public static string Host =>
        OperatingSystem.IsWindows() ? PlatformScope.Windows : PlatformScope.Linux;

    /// <summary>
    /// Maps a requested selection (<c>auto</c>/<c>windows</c>/<c>linux</c>/null) to a concrete
    /// platform. <c>auto</c> and unknown values fall back to <see cref="Host"/>.
    /// </summary>
    public static string Resolve(string? requested)
    {
        var value = (requested ?? PlatformScope.Auto).Trim().ToLowerInvariant();
        return value switch
        {
            PlatformScope.Windows => PlatformScope.Windows,
            PlatformScope.Linux => PlatformScope.Linux,
            _ => Host,
        };
    }
}
