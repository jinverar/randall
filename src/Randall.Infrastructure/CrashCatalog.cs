using System.Diagnostics;
using Randall.Contracts;

namespace Randall.Infrastructure;

public static class CrashCatalog
{
    public static string? FindRepoRoot()
    {
        var dir = new DirectoryInfo(Directory.GetCurrentDirectory());
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Randall.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }
        return null;
    }

    public static IReadOnlyList<CrashSummaryDto> ListAll(string? repoRoot = null, string? projectFilter = null)
    {
        repoRoot ??= FindRepoRoot();
        if (repoRoot is null)
            return [];

        var crashesRoot = Path.Combine(repoRoot, "data", "crashes");
        if (!Directory.Exists(crashesRoot))
            return [];

        var results = new List<CrashSummaryDto>();
        foreach (var dir in Directory.EnumerateDirectories(crashesRoot))
        {
            var projectName = Path.GetFileName(dir);
            if (projectFilter is not null &&
                !projectName.Equals(projectFilter, StringComparison.OrdinalIgnoreCase))
                continue;

            var store = new CrashStore(dir);
            foreach (var c in store.List())
            {
                results.Add(new CrashSummaryDto(
                    c.Id,
                    c.Project,
                    c.Iteration,
                    c.Mutator,
                    c.InputHash,
                    c.InputPath,
                    c.MiniDumpPath,
                    c.TargetExitCode,
                    c.At));
            }
        }

        return results.OrderByDescending(c => c.ObservedAt).ToList();
    }

    public static IReadOnlyList<CrashClusterDto> ListClusters(string? repoRoot = null, string? projectFilter = null)
    {
        var crashes = ListAll(repoRoot, projectFilter);
        return CrashCluster.Build(crashes)
            .Select(c => new CrashClusterDto(
                c.ClusterId,
                c.Project,
                c.Count,
                c.RepresentativeId,
                c.RepresentativeHash,
                c.RepresentativeMutator,
                c.LengthBucket))
            .ToList();
    }

    public static CrashDetailDto? GetDetail(Guid id, string? repoRoot = null)
    {
        foreach (var summary in ListAll(repoRoot))
        {
            if (summary.Id != id)
                continue;
            if (!File.Exists(summary.InputPath))
                return new CrashDetailDto(summary, 0, "(file missing)");

            var bytes = File.ReadAllBytes(summary.InputPath);
            var previewLen = Math.Min(bytes.Length, 256);
            var hex = string.Join(' ', bytes.AsSpan(0, previewLen).ToArray().Select(b => b.ToString("X2")));
            if (bytes.Length > previewLen)
                hex += " …";
            return new CrashDetailDto(summary, bytes.Length, hex);
        }
        return null;
    }

    public static IReadOnlyList<TargetProfileDto> ListTargets(string? repoRoot = null)
    {
        repoRoot ??= FindRepoRoot();
        if (repoRoot is null)
            return [];

        var projectsDir = Path.Combine(repoRoot, "projects");
        var list = new List<TargetProfileDto>();
        foreach (var path in DiscoverAllProjects(projectsDir))
        {
            try
            {
                var p = ProjectLoader.Load(path);
                list.Add(new TargetProfileDto(p.Name, p.Kind, p.Description, path));
            }
            catch { /* skip invalid project */ }
        }
        return list;
    }

    private static IEnumerable<string> DiscoverAllProjects(string projectsDir)
    {
        foreach (var path in ProjectLoader.DiscoverProjects(projectsDir))
            yield return path;

        var localDir = Path.Combine(projectsDir, "local");
        foreach (var path in ProjectLoader.DiscoverProjects(localDir))
            yield return path;
    }
}

public sealed class ReplayEngine
{
    public async Task<TargetRunResult> ReplayAsync(
        ProjectConfig project,
        string yamlPath,
        byte[] payload,
        CancellationToken cancellationToken = default)
    {
        Process? server = null;
        if (project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase) && project.Target.LongLived)
            server = TargetRunner.StartTarget(project, yamlPath, null);

        try
        {
            return await TargetRunner.RunPayloadAsync(project, yamlPath, payload, server, cancellationToken);
        }
        finally
        {
            if (server is { HasExited: false })
            {
                server.Kill(entireProcessTree: true);
                server.Dispose();
            }
        }
    }
}
