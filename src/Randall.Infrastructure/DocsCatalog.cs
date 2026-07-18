using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Serve allowlisted markdown from repo docs/ for the in-app Help view.</summary>
public static class DocsCatalog
{
    public static readonly (string Path, string Title, string Group)[] Index =
    [
        ("CUSTOM_TARGETS.md", "Custom targets (YAML → Target profile)", "Getting started"),
        ("CASE_BUILDER.md", "Scare Floor — recipes, seeds & dictionaries", "Getting started"),
        ("LORE.md", "Mascot lore (Randall)", "Project"),
        ("TARGETS.md", "Lab targets", "Getting started"),
        ("FUZZING.md", "Fuzzing techniques & mutators", "Fuzzing"),
        ("STALKING.md", "Stalking bugs", "Stalk & scream"),
        ("CRASH_ANALYSIS.md", "Crash analysis", "Stalk & scream"),
        ("LAB_PRACTICE.md", "Lab practice walkthrough", "Lab"),
        ("MODEL.md", "Protocol models", "Lab"),
        ("ROADMAP.md", "Roadmap", "Project"),
        ("ARCHITECTURE.md", "Architecture", "Project"),
    ];

    public static IReadOnlyList<DocIndexEntryDto> List() =>
        Index.Select(i => new DocIndexEntryDto(i.Path, i.Title, i.Group)).ToList();

    public static DocContentDto? Read(string relativePath, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot();
        if (repoRoot is null)
            return null;

        var safe = NormalizeDocPath(relativePath);
        if (safe is null)
            return null;

        var full = Path.GetFullPath(Path.Combine(repoRoot, "docs", safe));
        var docsRoot = Path.GetFullPath(Path.Combine(repoRoot, "docs")) + Path.DirectorySeparatorChar;
        if (!full.StartsWith(docsRoot, StringComparison.OrdinalIgnoreCase) || !File.Exists(full))
            return null;

        if (!full.EndsWith(".md", StringComparison.OrdinalIgnoreCase) &&
            !full.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
            return null;

        var title = Index.FirstOrDefault(i =>
            i.Path.Equals(safe.Replace('\\', '/'), StringComparison.OrdinalIgnoreCase)).Title
            ?? Path.GetFileNameWithoutExtension(safe);
        var markdown = File.ReadAllText(full);
        return new DocContentDto(safe.Replace('\\', '/'), title, markdown);
    }

    private static string? NormalizeDocPath(string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath))
            return null;
        var s = relativePath.Replace('\\', '/').Trim().TrimStart('/');
        if (s.Contains("..", StringComparison.Ordinal) || Path.IsPathRooted(s))
            return null;
        // Allow templates/*.yaml as text too
        if (s.StartsWith("templates/", StringComparison.OrdinalIgnoreCase))
            return s;
        if (!s.EndsWith(".md", StringComparison.OrdinalIgnoreCase) &&
            !s.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) &&
            !s.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase))
            return null;
        return s;
    }
}
