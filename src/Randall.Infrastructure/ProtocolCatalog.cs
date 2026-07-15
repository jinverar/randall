using Randall.Contracts;

namespace Randall.Infrastructure;

public static class ProtocolCatalog
{
    public static IReadOnlyList<ProtocolSummaryDto> ListAll(string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot();
        if (repoRoot is null)
            return [];

        var projectsDir = Path.Combine(repoRoot, "projects");
        var protocolsDir = Path.Combine(projectsDir, "protocols");
        var projectYaml = Path.Combine(projectsDir, "vulnserver.yaml");
        if (!File.Exists(projectYaml))
            projectYaml = projectsDir;

        var list = new List<ProtocolSummaryDto>();
        foreach (var path in ProtocolLoader.Discover(protocolsDir))
        {
            try
            {
                var rel = Path.GetRelativePath(projectsDir, path).Replace('\\', '/');
                if (!rel.StartsWith("protocols/", StringComparison.OrdinalIgnoreCase))
                    rel = "protocols/" + Path.GetFileName(path);
                var summary = ProtocolLoader.Describe(rel, projectYaml);
                list.Add(summary with { Path = rel });
            }
            catch { /* skip */ }
        }
        return list;
    }
}
