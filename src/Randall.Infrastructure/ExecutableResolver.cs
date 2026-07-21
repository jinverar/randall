namespace Randall.Infrastructure;

/// <summary>
/// Cross-platform executable resolution. Lab profiles are authored with Windows <c>.exe</c> paths,
/// but the same .NET lab targets build to an extensionless apphost on Linux/macOS. This maps a
/// declared path to whatever actually exists on the current OS so one profile works on both:
/// on Linux a <c>foo.exe</c> reference also matches a sibling <c>foo</c>; on Windows a bare
/// <c>foo</c> also matches <c>foo.exe</c>.
/// </summary>
public static class ExecutableResolver
{
    /// <summary>Returns an existing executable path for <paramref name="resolvedPath"/>, or null.</summary>
    public static string? FindExisting(string? resolvedPath)
    {
        if (string.IsNullOrWhiteSpace(resolvedPath))
            return null;
        if (File.Exists(resolvedPath))
            return resolvedPath;

        foreach (var candidate in Candidates(resolvedPath))
        {
            if (File.Exists(candidate))
                return candidate;
        }

        return null;
    }

    /// <summary>OS-appropriate alternate spellings of an executable path (no existence check).</summary>
    public static IEnumerable<string> Candidates(string resolvedPath)
    {
        var hasExe = resolvedPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
        if (OperatingSystem.IsWindows())
        {
            if (!hasExe)
                yield return resolvedPath + ".exe";
        }
        else
        {
            // Linux/macOS: the apphost has no extension.
            if (hasExe)
                yield return resolvedPath[..^4];
        }
    }
}
