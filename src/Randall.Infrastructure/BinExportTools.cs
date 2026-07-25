namespace Randall.Infrastructure;

/// <summary>
/// Optional BinExport (Ghidra extension) + BinDiff discovery for patch-hunt workflows.
/// Randfuzz does not ship or invoke the diff engines — doctor hints + install script only.
/// </summary>
public static class BinExportTools
{
    public sealed record Discovery(
        bool IsBinExportExtensionPresent,
        bool IsBinDiffAvailable,
        string? BinDiffPath,
        string? BinExportExtensionDir,
        string? CachedGhidraZip);

    public static Discovery Discover(string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot();
        var ghidra = GhidraTools.Discover(repoRoot);
        var extDir = FindBinExportExtension(ghidra.GhidraRunPath);
        var cachedZip = FindCachedGhidraZip(repoRoot);
        var bindiff = FindBinDiff(repoRoot);

        return new Discovery(
            extDir is not null || cachedZip is not null,
            bindiff is not null,
            bindiff,
            extDir,
            cachedZip);
    }

    public static string InstallHint =>
        OperatingSystem.IsWindows()
            ? "optional patch-hunt — scripts/install-binexport.ps1 (Ghidra extension + BinDiff notes)"
            : "optional patch-hunt — install Ghidra BinExport extension + BinDiff manually (see docs/GHIDRA_INTEGRATION.md)";

    public static string? FindBinDiff(string? repoRoot = null)
    {
        var env = Environment.GetEnvironmentVariable("BINDIFF_HOME");
        if (!string.IsNullOrWhiteSpace(env))
        {
            var fromEnv = FindBinDiffUnder(env);
            if (fromEnv is not null)
                return fromEnv;
        }

        if (repoRoot is not null)
        {
            var local = Path.Combine(repoRoot, "tools", "bindiff", "bin", "bindiff.exe");
            if (File.Exists(local))
                return local;
            local = Path.Combine(repoRoot, "tools", "bindiff", "bindiff.exe");
            if (File.Exists(local))
                return local;
        }

        return FindOnPath("bindiff.exe", "bindiff");
    }

    internal static string? FindBinExportExtension(string? ghidraRunPath)
    {
        if (string.IsNullOrWhiteSpace(ghidraRunPath))
            return null;

        var ghidraHome = Path.GetDirectoryName(ghidraRunPath)!;
        if (!File.Exists(Path.Combine(ghidraHome, "support", OperatingSystem.IsWindows() ? "analyzeHeadless.bat" : "analyzeHeadless")))
        {
            var parent = Directory.GetParent(ghidraHome)?.FullName;
            if (parent is not null)
                ghidraHome = parent;
        }

        var extensions = Path.Combine(ghidraHome, "Ghidra", "Extensions");
        if (!Directory.Exists(extensions))
            return null;

        foreach (var dir in Directory.EnumerateDirectories(extensions))
        {
            var name = Path.GetFileName(dir);
            if (name.Contains("BinExport", StringComparison.OrdinalIgnoreCase))
                return dir;
        }

        return null;
    }

    internal static string? FindCachedGhidraZip(string? repoRoot)
    {
        if (repoRoot is null)
            return null;

        var dist = Path.Combine(repoRoot, "tools", "binexport", "dist");
        if (!Directory.Exists(dist))
            return null;

        return Directory.EnumerateFiles(dist, "*BinExport*.zip", SearchOption.TopDirectoryOnly)
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .FirstOrDefault();
    }

    private static string? FindBinDiffUnder(string home)
    {
        if (!Directory.Exists(home))
            return null;

        foreach (var name in new[] { "bindiff.exe", "bindiff" })
        {
            var direct = Path.Combine(home, name);
            if (File.Exists(direct))
                return direct;
        }

        var bin = Path.Combine(home, "bin", OperatingSystem.IsWindows() ? "bindiff.exe" : "bindiff");
        return File.Exists(bin) ? bin : null;
    }

    private static string? FindOnPath(params string[] names)
    {
        var pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(pathEnv))
            return null;

        foreach (var part in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (var name in names)
            {
                var candidate = Path.Combine(part.Trim(), name);
                if (File.Exists(candidate))
                    return candidate;
            }
        }

        return null;
    }
}
