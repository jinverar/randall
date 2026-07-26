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
            return Defaults(host);

        try
        {
            var dto = JsonSerializer.Deserialize<UiPrefsDto>(File.ReadAllText(path), JsonOpts);
            if (dto is null)
                return Defaults(host);
            var theme = IsValidTheme(dto.Theme) ? NormalizeTheme(dto.Theme) : "light";
            var platform = NormalizePlatform(dto.Platform);
            var level = ResolveInstructorLevel(dto.InstructorLevel, dto.InstructorMode);
            return new UiPrefsDto(theme, platform, host, dto.ScreamCanisters, dto.ScreamAnimations,
                NormalizePresentationMode(dto.PresentationMode),
                InstructorAssistance.ToInstructorMode(level),
                level);
        }
        catch
        {
            return Defaults(host);
        }
    }

    public static UiPrefsDto Save(UiPrefsDto prefs, string? repoRoot = null)
    {
        var theme = IsValidTheme(prefs.Theme) ? NormalizeTheme(prefs.Theme) : "light";
        var platform = NormalizePlatform(prefs.Platform);
        var level = ResolveInstructorLevel(prefs.InstructorLevel, prefs.InstructorMode);
        var path = PrefsPath(repoRoot);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        // HostPlatform is intentionally left null on disk — it is a live value stamped by Get().
        var saved = new UiPrefsDto(theme, platform, null, prefs.ScreamCanisters, prefs.ScreamAnimations,
            NormalizePresentationMode(prefs.PresentationMode),
            InstructorAssistance.ToInstructorMode(level),
            level);
        File.WriteAllText(path, JsonSerializer.Serialize(saved, JsonOpts));
        return saved with { HostPlatform = PlatformResolver.Host };
    }

    public static bool IsValidTheme(string? theme) =>
        !string.IsNullOrWhiteSpace(theme) && AllowedThemes.Contains(theme);

    public static string NormalizeTheme(string theme) => theme.Trim().ToLowerInvariant();

    public static bool IsValidPlatform(string? platform) => PlatformScope.IsSelectable(platform);

    public static string NormalizePlatform(string? platform) =>
        PlatformScope.IsSelectable(platform) ? platform!.Trim().ToLowerInvariant() : PlatformScope.Auto;

    private static UiPrefsDto Defaults(string host) =>
        new("light", PlatformScope.Auto, host, ScreamCanisters: true, ScreamAnimations: false,
            PresentationMode: "research", InstructorMode: false, InstructorLevel: 0);

    public static bool IsValidPresentationMode(string? mode) =>
        !string.IsNullOrWhiteSpace(mode)
        && (mode.Equals("learning", StringComparison.OrdinalIgnoreCase)
            || mode.Equals("research", StringComparison.OrdinalIgnoreCase));

    public static string NormalizePresentationMode(string? mode) =>
        mode?.Equals("learning", StringComparison.OrdinalIgnoreCase) == true ? "learning" : "research";

    /// <summary>
    /// Prefer explicit level when set; otherwise map legacy InstructorMode bool (true → 1).
    /// </summary>
    public static int ResolveInstructorLevel(int level, bool instructorMode)
    {
        // Level takes precedence when non-zero, or when mode is off (level 0).
        // If persisted file only had InstructorMode=true (level default 0), promote to 1.
        if (level > 0)
            return InstructorAssistance.Normalize(level);
        if (instructorMode)
            return 1;
        return InstructorAssistance.Normalize(level);
    }

    private static string PrefsPath(string? repoRoot)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        return Path.Combine(repoRoot, "data", "ui-prefs.json");
    }
}
