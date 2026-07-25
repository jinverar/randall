using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Reconstruct mutator ancestry from crash sidecar + run journal (iterations.jsonl).
/// </summary>
public static class CrashLineageResolver
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public static CrashLineageDto? Resolve(CrashSidecarDto? sidecar, string? repoRoot = null)
    {
        if (sidecar is null)
            return null;

        var chain = sidecar.MutatorChain?.ToList() ?? [];
        if (chain.Count == 0 && !string.IsNullOrWhiteSpace(sidecar.Mutator))
            chain.Add(sidecar.Mutator);

        var partial = true;
        if (!string.IsNullOrWhiteSpace(sidecar.RunId) && sidecar.Iteration > 0)
        {
            var journalChain = TryReplayJournal(sidecar, repoRoot);
            if (journalChain.Count > 0)
            {
                chain = journalChain;
                partial = false;
            }
        }

        if (chain.Count == 0 && sidecar.ParentInputHash is null && sidecar.SeedSource is null)
            return null;

        return new CrashLineageDto(
            chain,
            sidecar.ParentInputHash,
            sidecar.SeedSource,
            Partial: partial);
    }

    private static List<string> TryReplayJournal(CrashSidecarDto sidecar, string? repoRoot)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var runDir = FindRunDirectory(sidecar.RunId, sidecar.Project, repoRoot);
        if (runDir is null)
            return [];

        var iterPath = Path.Combine(runDir, "iterations.jsonl");
        if (!File.Exists(iterPath))
            return [];

        var entries = new List<IterationLogEntry>();
        foreach (var line in File.ReadLines(iterPath))
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;
            try
            {
                var entry = JsonSerializer.Deserialize<IterationLogEntry>(line, JsonOptions);
                if (entry is not null)
                    entries.Add(entry);
            }
            catch
            {
                /* skip bad lines */
            }
        }

        if (entries.Count == 0)
            return [];

        var byHash = entries
            .GroupBy(e => e.PayloadHash, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Last(), StringComparer.OrdinalIgnoreCase);

        var start = entries.LastOrDefault(e => e.Iteration == sidecar.Iteration)
                    ?? entries.LastOrDefault(e =>
                        e.PayloadHash.Equals(sidecar.InputHash, StringComparison.OrdinalIgnoreCase));
        if (start is null)
            return [];

        var chain = new List<string>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var current = start;

        while (current is not null && visited.Add(current.PayloadHash))
        {
            if (current.MutatorChain is { Count: > 0 })
            {
                foreach (var m in current.MutatorChain)
                {
                    if (!string.IsNullOrWhiteSpace(m) && (chain.Count == 0 || chain[^1] != m))
                        chain.Add(m);
                }
            }
            else if (!string.IsNullOrWhiteSpace(current.Mutator))
            {
                if (chain.Count == 0 || chain[^1] != current.Mutator)
                    chain.Add(current.Mutator);
            }

            if (string.IsNullOrWhiteSpace(current.ParentInputHash))
                break;

            if (!byHash.TryGetValue(current.ParentInputHash, out var parent))
                break;

            current = parent;
        }

        chain.Reverse();
        return chain;
    }

    private static string? FindRunDirectory(string runId, string project, string repoRoot)
    {
        var direct = Path.Combine(repoRoot, "data", "runs", runId);
        if (Directory.Exists(direct))
            return direct;

        var yaml = FindProjectYaml(repoRoot, project);
        if (yaml is null)
            return null;

        try
        {
            var cfg = ProjectLoader.Load(yaml);
            var runsRoot = ProjectLoader.ResolvePath(yaml, cfg.Fuzz.RunsDir);
            if (!Directory.Exists(runsRoot))
                return null;

            var candidate = Path.Combine(runsRoot, runId);
            return Directory.Exists(candidate) ? candidate : null;
        }
        catch
        {
            return null;
        }
    }

    private static string? FindProjectYaml(string repoRoot, string project)
    {
        var name = project.Trim();
        foreach (var candidate in new[]
                 {
                     Path.Combine(repoRoot, "projects", name + ".yaml"),
                     Path.Combine(repoRoot, "projects", name + ".yml"),
                     Path.Combine(repoRoot, "projects", "local", name + ".yaml"),
                 })
        {
            if (File.Exists(candidate))
                return candidate;
        }

        foreach (var path in ProjectLoader.DiscoverAll(repoRoot))
        {
            try
            {
                var p = ProjectLoader.Load(path);
                if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase))
                    return path;
            }
            catch
            {
                /* ignore */
            }
        }

        return null;
    }
}
