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

    public static UiPrefsDto Get(string? repoRoot = null)
    {
        var path = PrefsPath(repoRoot);
        if (!File.Exists(path))
            return new UiPrefsDto("dark");

        try
        {
            var dto = JsonSerializer.Deserialize<UiPrefsDto>(File.ReadAllText(path), JsonOpts);
            if (dto is null || !IsValidTheme(dto.Theme))
                return new UiPrefsDto("dark");
            return new UiPrefsDto(NormalizeTheme(dto.Theme));
        }
        catch
        {
            return new UiPrefsDto("dark");
        }
    }

    public static UiPrefsDto Save(UiPrefsDto prefs, string? repoRoot = null)
    {
        var theme = IsValidTheme(prefs.Theme) ? NormalizeTheme(prefs.Theme) : "dark";
        var path = PrefsPath(repoRoot);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var saved = new UiPrefsDto(theme);
        File.WriteAllText(path, JsonSerializer.Serialize(saved, JsonOpts));
        return saved;
    }

    public static bool IsValidTheme(string? theme) =>
        !string.IsNullOrWhiteSpace(theme) && AllowedThemes.Contains(theme);

    public static string NormalizeTheme(string theme) => theme.Trim().ToLowerInvariant();

    private static string PrefsPath(string? repoRoot)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        return Path.Combine(repoRoot, "data", "ui-prefs.json");
    }
}
