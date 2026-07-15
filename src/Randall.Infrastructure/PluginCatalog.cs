using Randall.Contracts;

namespace Randall.Infrastructure;

public static class PluginCatalog
{
    public static IReadOnlyList<PluginInfoDto> ListAll(string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot();
        if (repoRoot is null)
            return [];

        var pluginsDir = Path.Combine(repoRoot, "plugins");
        return RppPluginHost.Discover(pluginsDir)
            .Select(p => new PluginInfoDto(
                p.Manifest.Name,
                p.Manifest.Runtime,
                p.Manifest.Hook,
                Path.Combine(p.Dir, "rpp.yaml")))
            .ToList();
    }

    public static IReadOnlyList<string> ListCampaigns(string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot();
        if (repoRoot is null)
            return [];
        return CampaignLoader.Discover(Path.Combine(repoRoot, "campaigns")).ToList();
    }
}
