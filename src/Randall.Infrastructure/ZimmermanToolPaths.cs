namespace Randall.Infrastructure;

/// <summary>
/// Resolve Eric Zimmerman (EZ) forensic CLIs from <c>tools/ez/</c>, <c>tools/</c>, PATH,
/// or common install folders. Binaries are not committed — see docs/MINI_TIMELINE.md.
/// </summary>
public static class ZimmermanToolPaths
{
    public static string? Find(string? repoRoot, params string[] fileNames)
    {
        if (fileNames.Length == 0)
            return null;

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        foreach (var dir in CandidateDirs(repoRoot))
        {
            foreach (var name in fileNames)
            {
                var local = Path.Combine(dir, name);
                if (File.Exists(local))
                    return local;
            }
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

        return null;
    }

    public static IEnumerable<string> CandidateDirs(string repoRoot)
    {
        yield return Path.Combine(repoRoot, "tools", "ez");
        yield return Path.Combine(repoRoot, "tools", "Zimmerman");
        yield return Path.Combine(repoRoot, "tools", "zimmerman");
        yield return Path.Combine(repoRoot, "tools");
        foreach (var root in new[]
                 {
                     @"C:\EZTools",
                     @"C:\tools\ez",
                     @"C:\tools\Zimmerman",
                     Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "EZTools"),
                 })
        {
            if (!string.IsNullOrWhiteSpace(root))
                yield return root;
        }
    }

    public static string? FindEvtxECmd(string? repoRoot = null) =>
        Find(repoRoot, "EvtxECmd.exe", "evtxecmd.exe");

    public static string? FindMFTECmd(string? repoRoot = null) =>
        Find(repoRoot, "MFTECmd.exe", "mftecmd.exe");

    public static string? FindPECmd(string? repoRoot = null) =>
        Find(repoRoot, "PECmd.exe", "pecmd.exe");

    public static string? FindAmcacheParser(string? repoRoot = null) =>
        Find(repoRoot, "AmcacheParser.exe", "amcacheparser.exe");

    public static string? FindAppCompatCacheParser(string? repoRoot = null) =>
        Find(repoRoot, "AppCompatCacheParser.exe", "appcompatcacheparser.exe");

    public static string? FindBstrings(string? repoRoot = null) =>
        Find(repoRoot, "bstrings.exe", "Bstrings.exe");

    public static MiniTimelineToolStatus Probe(string? repoRoot = null) =>
        new(
            FindEvtxECmd(repoRoot),
            FindMFTECmd(repoRoot),
            FindPECmd(repoRoot),
            FindAmcacheParser(repoRoot),
            FindAppCompatCacheParser(repoRoot),
            FindBstrings(repoRoot));
}

public sealed record MiniTimelineToolStatus(
    string? EvtxECmd,
    string? MFTECmd,
    string? PECmd,
    string? AmcacheParser,
    string? AppCompatCacheParser,
    string? Bstrings)
{
    public bool HasCore => EvtxECmd is not null || MFTECmd is not null;

    public IReadOnlyList<string> FoundLines()
    {
        var lines = new List<string>();
        void Add(string label, string? path)
        {
            if (path is not null)
                lines.Add($"{label}: {path}");
        }

        Add("EvtxECmd", EvtxECmd);
        Add("MFTECmd", MFTECmd);
        Add("PECmd", PECmd);
        Add("AmcacheParser", AmcacheParser);
        Add("AppCompatCacheParser", AppCompatCacheParser);
        Add("bstrings", Bstrings);
        return lines;
    }
}
