using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Persisted update check / dismiss state under data/update-state.json.</summary>
public static class UpdateStateStore
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public sealed class State
    {
        public string? LastCheckedVersion { get; set; }
        public DateTimeOffset? LastCheckedAt { get; set; }
        public bool UpdateAvailable { get; set; }
        public bool MajorUpdate { get; set; }
        public bool SignatureValid { get; set; }
        public string? NotesUrl { get; set; }
        public string? Channel { get; set; }
        public string? Severity { get; set; }
        public string? Message { get; set; }
        public string? DismissedVersion { get; set; }
        public string? MatchedAssetFile { get; set; }
        public string? MatchedAssetSha256 { get; set; }
        public long? MatchedAssetSize { get; set; }
        public string? ReleaseTag { get; set; }
        public string? LastMajorNotifiedVersion { get; set; }
    }

    public static State Load(string? repoRoot = null)
    {
        var path = PathFor(repoRoot);
        if (!File.Exists(path))
            return new State();
        try
        {
            return JsonSerializer.Deserialize<State>(File.ReadAllText(path), JsonOpts) ?? new State();
        }
        catch
        {
            return new State();
        }
    }

    public static void Save(State state, string? repoRoot = null)
    {
        var path = PathFor(repoRoot);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(state, JsonOpts));
    }

    public static UpdateStatusDto ToStatus(State s, string installMode)
    {
        var dismissed = !string.IsNullOrWhiteSpace(s.DismissedVersion)
                        && string.Equals(s.DismissedVersion, s.LastCheckedVersion, StringComparison.OrdinalIgnoreCase);
        // Only raise the banner for signature-valid major updates.
        var banner = s.UpdateAvailable && s.MajorUpdate && s.SignatureValid && !dismissed;
        return new UpdateStatusDto(
            AppVersion.Version,
            installMode,
            s.LastCheckedVersion,
            s.LastCheckedAt,
            s.UpdateAvailable,
            s.MajorUpdate,
            s.SignatureValid,
            s.NotesUrl,
            s.DismissedVersion,
            BannerSuppressed: !banner,
            s.Message);
    }

    private static string PathFor(string? repoRoot)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        return Path.Combine(repoRoot, "data", "update-state.json");
    }
}
