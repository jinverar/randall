using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Coverage-guided corpus minimization (AFL cmin-style scaffold).
/// Keeps the smallest set of inputs that preserve observed edge / path novelty keys.
/// </summary>
public static class CorpusMinimizer
{
    public sealed record Result(
        bool Ok,
        string Message,
        int InputCount,
        int KeptCount,
        string OutputDir);

    /// <summary>
    /// Minimize a corpus directory using edge keys from companion coverage files when present,
    /// otherwise content-hash novelty (honest fallback when no BB provider).
    /// </summary>
    public static Result Minimize(
        string corpusDir,
        string? outputDir = null,
        bool dryRun = false)
    {
        if (!Directory.Exists(corpusDir))
            return new Result(false, $"Corpus not found: {corpusDir}", 0, 0, outputDir ?? "");

        outputDir ??= Path.Combine(corpusDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + "_min");
        var inputs = Directory.EnumerateFiles(corpusDir, "*", SearchOption.TopDirectoryOnly)
            .Where(f => !Path.GetFileName(f).StartsWith('.') &&
                        !Path.GetFileName(f).Equals("paths.txt", StringComparison.OrdinalIgnoreCase) &&
                        !Path.GetFileName(f).EndsWith(".txt", StringComparison.OrdinalIgnoreCase) &&
                        !Path.GetFileName(f).EndsWith(".json", StringComparison.OrdinalIgnoreCase) &&
                        Directory.GetParent(f)?.Name != "_tmp" &&
                        Directory.GetParent(f)?.Name != "traces" &&
                        Directory.GetParent(f)?.Name != "traces-binary")
            .Where(f =>
            {
                var name = Path.GetFileName(f);
                return !name.StartsWith("fuzz_", StringComparison.OrdinalIgnoreCase);
            })
            .OrderBy(f => new FileInfo(f).Length)
            .ThenBy(f => f, StringComparer.OrdinalIgnoreCase)
            .ToList();

        // Prefer files that look like seeds / queue entries.
        if (inputs.Count == 0)
        {
            inputs = Directory.EnumerateFiles(corpusDir, "*", SearchOption.AllDirectories)
                .Where(f =>
                {
                    var rel = Path.GetRelativePath(corpusDir, f);
                    if (rel.Contains("_tmp", StringComparison.OrdinalIgnoreCase)) return false;
                    if (rel.Contains("traces", StringComparison.OrdinalIgnoreCase)) return false;
                    var ext = Path.GetExtension(f);
                    return ext is not ".txt" and not ".json" and not ".jsonl" and not ".log";
                })
                .OrderBy(f => new FileInfo(f).Length)
                .ToList();
        }

        var covered = new HashSet<string>(StringComparer.Ordinal);
        var kept = new List<string>();

        foreach (var path in inputs)
        {
            var keys = LoadCoverageKeys(path, corpusDir);
            if (keys.Count == 0)
                keys = [ContentKey(path)];

            var novel = keys.Where(k => covered.Add(k)).Any();
            if (!novel && kept.Count > 0)
                continue;
            if (!novel && kept.Count == 0)
            {
                // First input always kept to avoid empty corpus.
                foreach (var k in keys) covered.Add(k);
            }
            kept.Add(path);
        }

        if (!dryRun)
        {
            Directory.CreateDirectory(outputDir);
            foreach (var src in kept)
            {
                var dest = Path.Combine(outputDir, Path.GetFileName(src));
                File.Copy(src, dest, overwrite: true);
            }
        }

        var msg =
            $"Kept {kept.Count}/{inputs.Count} inputs " +
            $"({covered.Count} coverage keys). " +
            (dryRun ? "Dry-run — no files written." : $"Wrote {outputDir}");
        return new Result(true, msg, inputs.Count, kept.Count, outputDir);
    }

    public static Result MinimizeProject(ProjectConfig project, string yamlPath, bool dryRun = false)
    {
        var corpus = ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CorpusDir);
        var outDir = Path.Combine(corpus.TrimEnd(Path.DirectorySeparatorChar) + "_min");
        return Minimize(corpus, outDir, dryRun);
    }

    private static IReadOnlyList<string> LoadCoverageKeys(string inputPath, string corpusDir)
    {
        var keys = new List<string>();
        // Companion edge list next to input or under traces/
        var edgeSibling = inputPath + ".edges";
        if (File.Exists(edgeSibling))
            keys.AddRange(File.ReadAllLines(edgeSibling).Where(l => l.Length > 0));

        var traces = Path.Combine(corpusDir, "traces");
        if (Directory.Exists(traces))
        {
            var stem = Path.GetFileNameWithoutExtension(inputPath);
            foreach (var log in Directory.EnumerateFiles(traces, "*.log"))
            {
                if (!Path.GetFileName(log).Contains(stem, StringComparison.OrdinalIgnoreCase))
                    continue;
                try
                {
                    foreach (var line in File.ReadLines(log).Take(4000))
                    {
                        if (line.Contains("0x", StringComparison.OrdinalIgnoreCase))
                            keys.Add(line.Trim());
                    }
                }
                catch { /* ignore */ }
            }
        }

        var pathsFile = Path.Combine(corpusDir, "paths.txt");
        if (File.Exists(pathsFile))
        {
            // Semantic-stage keys — weak association: include all known stages as global set marker.
            // Per-input path logs use *.paths beside temp files (ephemeral); corpus paths.txt is global.
            keys.Add("paths.txt:" + ContentKey(pathsFile));
        }

        return keys.Distinct(StringComparer.Ordinal).ToList();
    }

    private static string ContentKey(string path)
    {
        try
        {
            var bytes = File.ReadAllBytes(path);
            return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes))[..16];
        }
        catch
        {
            return path;
        }
    }
}
