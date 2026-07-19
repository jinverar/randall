namespace Randall.Infrastructure;

/// <summary>
/// Resolve Sysinternals binaries from <c>tools/</c>, PATH, or common install folders.
/// Binaries are not committed — copy from the Sysinternals Suite (see tools/README.md).
/// </summary>
public static class SysinternalsToolPaths
{
    public static string? Find(string? repoRoot, params string[] fileNames)
    {
        if (fileNames.Length == 0)
            return null;

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var tools = Path.Combine(repoRoot, "tools");
        foreach (var name in fileNames)
        {
            var local = Path.Combine(tools, name);
            if (File.Exists(local))
                return local;
        }

        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathEnv.Split(Path.PathSeparator))
        {
            if (string.IsNullOrWhiteSpace(dir)) continue;
            foreach (var name in fileNames)
            {
                var candidate = Path.Combine(dir.Trim('"'), name);
                if (File.Exists(candidate))
                    return candidate;
            }
        }

        foreach (var root in new[] { @"C:\Sysinternals", @"C:\tools\Sysinternals", @"C:\tools" })
        {
            foreach (var name in fileNames)
            {
                var candidate = Path.Combine(root, name);
                if (File.Exists(candidate))
                    return candidate;
            }
        }

        return null;
    }

    public static string? FindHandle(string? repoRoot = null) =>
        Find(repoRoot, "handle64.exe", "handle.exe");

    public static string? FindListDlls(string? repoRoot = null) =>
        Find(repoRoot, "listdlls64.exe", "listdlls.exe", "ListDLLs64.exe", "ListDLLs.exe");

    public static string? FindPsList(string? repoRoot = null) =>
        Find(repoRoot, "pslist64.exe", "pslist.exe");

    public static string? FindDebugView(string? repoRoot = null) =>
        Find(repoRoot, "Dbgview.exe", "dbgview.exe", "Dbgview64.exe");

    public static string? FindPsInfo(string? repoRoot = null) =>
        Find(repoRoot, "PsInfo64.exe", "psinfo64.exe", "PsInfo.exe", "psinfo.exe");

    public static string? FindTcpvcon(string? repoRoot = null) =>
        Find(repoRoot, "tcpvcon64.exe", "Tcpvcon64.exe", "tcpvcon.exe", "Tcpvcon.exe");

    public static string? FindSigCheck(string? repoRoot = null) =>
        Find(repoRoot, "sigcheck64.exe", "Sigcheck64.exe", "sigcheck.exe", "Sigcheck.exe");

    public static string? FindStrings(string? repoRoot = null) =>
        Find(repoRoot, "strings64.exe", "Strings64.exe", "strings.exe", "Strings.exe");

    public static string? FindAccessChk(string? repoRoot = null) =>
        Find(repoRoot, "accesschk64.exe", "Accesschk64.exe", "accesschk.exe", "Accesschk.exe");

    public static string? FindVmMap(string? repoRoot = null) =>
        Find(repoRoot, "vmmap64.exe", "Vmmap64.exe", "vmmap.exe", "Vmmap.exe");
}
