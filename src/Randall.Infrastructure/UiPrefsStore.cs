using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Persisted console UI prefs (default skin, etc.) under data/ui-prefs.json.</summary>
public static class UiPrefsStore
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
    };

    private static readonly HashSet<string> AllowedThemes = new(StringComparer.OrdinalIgnoreCase)
    {
        "dark", "light", "cyber",
    };

    /// <summary>Returns stored prefs, always stamped with the live host platform (never persisted).</summary>
    public static UiPrefsDto Get(string? repoRoot = null)
    {
        var host = PlatformResolver.Host;
        var path = PrefsPath(repoRoot);
        if (!File.Exists(path))
            return new UiPrefsDto("light", PlatformScope.Auto, host);

        try
        {
            var dto = JsonSerializer.Deserialize<UiPrefsDto>(File.ReadAllText(path), JsonOpts);
            if (dto is null)
                return new UiPrefsDto("light", PlatformScope.Auto, host);
            var theme = IsValidTheme(dto.Theme) ? NormalizeTheme(dto.Theme) : "light";
            var platform = NormalizePlatform(dto.Platform);
            return new UiPrefsDto(theme, platform, host);
        }
        catch
        {
            return new UiPrefsDto("light", PlatformScope.Auto, host);
        }
    }

    public static UiPrefsDto Save(UiPrefsDto prefs, string? repoRoot = null)
    {
        var theme = IsValidTheme(prefs.Theme) ? NormalizeTheme(prefs.Theme) : "light";
        var platform = NormalizePlatform(prefs.Platform);
        var path = PrefsPath(repoRoot);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        // HostPlatform is intentionally left null on disk — it is a live value stamped by Get().
        var saved = new UiPrefsDto(theme, platform);
        File.WriteAllText(path, JsonSerializer.Serialize(saved, JsonOpts));
        return saved with { HostPlatform = PlatformResolver.Host };
    }

    public static bool IsValidTheme(string? theme) =>
        !string.IsNullOrWhiteSpace(theme) && AllowedThemes.Contains(theme);

    public static string NormalizeTheme(string theme) => theme.Trim().ToLowerInvariant();

    public static bool IsValidPlatform(string? platform) => PlatformScope.IsSelectable(platform);

    public static string NormalizePlatform(string? platform) =>
        PlatformScope.IsSelectable(platform) ? platform!.Trim().ToLowerInvariant() : PlatformScope.Auto;

    private static string PrefsPath(string? repoRoot)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        return Path.Combine(repoRoot, "data", "ui-prefs.json");
    }
}
