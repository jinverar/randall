using Randall.Contracts;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Randall.Infrastructure;

public static class ProjectLoader
{
    private static readonly IDeserializer Deserializer = new DeserializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    public static ProjectConfig Load(string yamlPath)
    {
        var full = Path.GetFullPath(yamlPath);
        if (!File.Exists(full))
            throw new FileNotFoundException($"Project file not found: {full}");
        var yaml = File.ReadAllText(full);
        var project = Deserializer.Deserialize<ProjectConfig>(yaml)
            ?? throw new InvalidOperationException($"Failed to parse project: {full}");
        project.Name = string.IsNullOrWhiteSpace(project.Name)
            ? Path.GetFileNameWithoutExtension(full)
            : project.Name;
        return project;
    }

    public static string ResolveProjectRoot(string yamlPath)
    {
        return Path.GetDirectoryName(Path.GetFullPath(yamlPath)) ?? Directory.GetCurrentDirectory();
    }

    public static string ResolvePath(string yamlPath, string relativePath)
    {
        if (Path.IsPathRooted(relativePath))
            return relativePath;
        var baseDir = ResolveProjectRoot(yamlPath);
        return Path.GetFullPath(Path.Combine(baseDir, relativePath));
    }
    public static byte[] LoadSeed(string yamlPath, string seedRelative)
    {
        var path = ResolvePath(yamlPath, seedRelative);
        if (!File.Exists(path))
            throw new FileNotFoundException($"Seed not found: {path}");
        return File.ReadAllBytes(path);
    }

    public static IEnumerable<string> DiscoverProjects(string projectsDir)
    {
        var dir = Path.GetFullPath(projectsDir);
        if (!Directory.Exists(dir))
            yield break;
        foreach (var file in Directory.EnumerateFiles(dir, "*.yaml"))
        {
            // Skip copy-templates (_TEMPLATE_tcp.yaml) — not live Target profiles
            if (Path.GetFileName(file).StartsWith("_", StringComparison.Ordinal))
                continue;
            yield return file;
        }
        foreach (var file in Directory.EnumerateFiles(dir, "*.yml"))
        {
            if (Path.GetFileName(file).StartsWith("_", StringComparison.Ordinal))
                continue;
            yield return file;
        }
    }

    /// <summary>Discover example projects under examples/*/project.yaml.</summary>
    public static IEnumerable<string> DiscoverExamples(string repoRoot)
    {
        var examplesDir = Path.Combine(repoRoot, "examples");
        if (!Directory.Exists(examplesDir))
            yield break;

        foreach (var projectFile in Directory.EnumerateFiles(examplesDir, "project.yaml", SearchOption.AllDirectories))
            yield return projectFile;
    }

    public static IEnumerable<string> DiscoverAll(string repoRoot)
    {
        var projectsDir = Path.Combine(repoRoot, "projects");
        foreach (var p in DiscoverProjects(projectsDir))
            yield return p;
        foreach (var p in DiscoverProjects(Path.Combine(projectsDir, "local")))
            yield return p;
        foreach (var p in DiscoverExamples(repoRoot))
            yield return p;
    }
}
