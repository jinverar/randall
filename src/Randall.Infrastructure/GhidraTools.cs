namespace Randall.Infrastructure;

/// <summary>
/// Discover Ghidra install + JDK for doctor and RE workflow hints.
/// Randfuzz Python importers live in committed <c>tools/ghidra/</c>; the Ghidra app is optional under
/// <c>tools/ghidra-app/</c> (Windows installer) or <c>GHIDRA_INSTALL_DIR</c>.
/// </summary>
public static class GhidraTools
{
    public sealed record Discovery(
        string? GhidraRunPath,
        string? JavaHome,
        string? ScriptsDir,
        bool IsGhidraAvailable,
        bool IsJavaAvailable);

    public static Discovery Discover(string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot();
        var scripts = repoRoot is not null ? Path.Combine(repoRoot, "tools", "ghidra") : null;
        var scriptsPresent = scripts is not null && Directory.Exists(scripts);

        var ghidraRun = FindGhidraRun(repoRoot);
        var javaHome = FindJavaHome();
        var javaOnPath = FindJavaOnPath();

        return new Discovery(
            ghidraRun,
            javaHome ?? javaOnPath?.JavaHome,
            scriptsPresent ? scripts : null,
            ghidraRun is not null,
            javaHome is not null || javaOnPath is not null);
    }

    public static string InstallHint =>
        OperatingSystem.IsWindows()
            ? "optional RE GUI — run scripts/install-ghidra.ps1 (~560 MB; needs JDK 21)"
            : "optional RE GUI — install Ghidra + JDK 21 (package manager) or extract under tools/ghidra-app";

    internal static string? FindGhidraRun(string? repoRoot)
    {
        var env = Environment.GetEnvironmentVariable("GHIDRA_INSTALL_DIR");
        if (!string.IsNullOrWhiteSpace(env))
        {
            var fromEnv = FindGhidraRunUnder(env);
            if (fromEnv is not null)
                return fromEnv;
        }

        if (repoRoot is not null)
        {
            var stable = Path.Combine(repoRoot, "tools", "ghidra-app");
            var fromStable = FindGhidraRunUnder(stable);
            if (fromStable is not null)
                return fromStable;

            var toolsDir = Path.Combine(repoRoot, "tools");
            if (Directory.Exists(toolsDir))
            {
                foreach (var dir in Directory.EnumerateDirectories(toolsDir, "ghidra_*"))
                {
                    var candidate = FindGhidraRunUnder(dir);
                    if (candidate is not null)
                        return candidate;
                }
            }
        }

        if (OperatingSystem.IsWindows())
        {
            foreach (var home in new[] { @"C:\ghidra", @"C:\tools\ghidra" })
            {
                var candidate = FindGhidraRunUnder(home);
                if (candidate is not null)
                    return candidate;
            }
        }
        else
        {
            foreach (var home in new[]
                     {
                         "/opt/ghidra",
                         "/usr/local/ghidra",
                         Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "ghidra"),
                     })
            {
                var candidate = FindGhidraRunUnder(home);
                if (candidate is not null)
                    return candidate;
            }
        }

        return FindGhidraRunOnPath();
    }

    internal static string? FindGhidraRunUnder(string home)
    {
        if (string.IsNullOrWhiteSpace(home) || !Directory.Exists(home))
            return null;

        foreach (var name in GhidraRunNames)
        {
            var path = Path.Combine(home, name);
            if (File.Exists(path))
                return path;
        }

        // One nested level (extracted zip layout: ghidra_12.x_PUBLIC/ghidraRun.bat).
        try
        {
            foreach (var sub in Directory.EnumerateDirectories(home))
            {
                foreach (var name in GhidraRunNames)
                {
                    var path = Path.Combine(sub, name);
                    if (File.Exists(path))
                        return path;
                }
            }
        }
        catch
        {
            // ignore unreadable dirs
        }

        return null;
    }

    private static string? FindGhidraRunOnPath()
    {
        var pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(pathEnv))
            return null;

        foreach (var part in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (var name in GhidraRunNames)
            {
                var candidate = Path.Combine(part.Trim(), name);
                if (File.Exists(candidate))
                    return candidate;
            }
        }

        return null;
    }

    internal static string? FindJavaHome()
    {
        var env = Environment.GetEnvironmentVariable("JAVA_HOME");
        if (!string.IsNullOrWhiteSpace(env) && Directory.Exists(env))
            return env.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        if (OperatingSystem.IsWindows())
        {
            foreach (var root in new[]
                     {
                         Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                         Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                         Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                             "Programs"),
                     })
            {
                if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
                    continue;

                try
                {
                    foreach (var dir in Directory.EnumerateDirectories(root, "*jdk*", SearchOption.TopDirectoryOnly))
                    {
                        if (LooksLikeJdk(dir))
                            return dir;
                    }

                    foreach (var dir in Directory.EnumerateDirectories(root, "Microsoft", SearchOption.TopDirectoryOnly))
                    {
                        foreach (var jdk in Directory.EnumerateDirectories(dir, "jdk-*", SearchOption.TopDirectoryOnly))
                        {
                            if (LooksLikeJdk(jdk))
                                return jdk;
                        }
                    }

                    foreach (var dir in Directory.EnumerateDirectories(root, "Eclipse Adoptium", SearchOption.TopDirectoryOnly))
                    {
                        foreach (var jdk in Directory.EnumerateDirectories(dir, "jdk-*", SearchOption.TopDirectoryOnly))
                        {
                            if (LooksLikeJdk(jdk))
                                return jdk;
                        }
                    }
                }
                catch
                {
                    // ignore permission / IO errors
                }
            }
        }
        else
        {
            foreach (var candidate in new[] { "/usr/lib/jvm/default-java", "/usr/lib/jvm/java-21-openjdk-amd64" })
            {
                if (Directory.Exists(candidate))
                    return candidate;
            }
        }

        return null;
    }

    internal static (string? JavaExe, string? JavaHome)? FindJavaOnPath()
    {
        var pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(pathEnv))
            return null;

        foreach (var part in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var javaName = OperatingSystem.IsWindows() ? "java.exe" : "java";
            var candidate = Path.Combine(part.Trim(), javaName);
            if (!File.Exists(candidate))
                continue;

            var home = Directory.GetParent(part.Trim())?.FullName;
            if (home is not null && string.Equals(Path.GetFileName(home), "bin", StringComparison.OrdinalIgnoreCase))
                home = Directory.GetParent(home)?.FullName;

            return (candidate, home);
        }

        return null;
    }

    private static bool LooksLikeJdk(string dir)
    {
        var javaName = OperatingSystem.IsWindows() ? "java.exe" : "java";
        return File.Exists(Path.Combine(dir, "bin", javaName));
    }

    private static readonly string[] GhidraRunNames = OperatingSystem.IsWindows()
        ? ["ghidraRun.bat", "ghidraRun"]
        : ["ghidraRun", "ghidraRun.bat"];
}
