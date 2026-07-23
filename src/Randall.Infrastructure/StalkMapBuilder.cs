using System.Globalization;
using Randall.Contracts;
using Randall.Infrastructure.ExploitSurface;

namespace Randall.Infrastructure;

/// <summary>
/// Builds an in-Randall stalk map: missed-block gaps + PE/ELF string/import surfaces.
/// Randall does light RE for fuzz guidance; Ghidra remains the deep microscope.
/// </summary>
public static class StalkMapBuilder
{
    public static StalkMapDto Build(
        string project,
        string? yamlPath = null,
        string? binaryPath = null,
        string? repoRoot = null,
        int limit = 60,
        FuzzSessionStatusDto? liveStatus = null)
    {
        if (string.IsNullOrWhiteSpace(project))
            throw new ArgumentException("project required");

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        limit = Math.Clamp(limit, 1, 200);

        var missed = MissedBlockAnalyzer.Analyze(project, repoRoot, limit: Math.Max(limit, 80), liveStatus);
        var resolvedBinary = ResolveBinary(project, yamlPath, binaryPath, repoRoot);
        var surface = BinarySurfaceMap.TryLoad(resolvedBinary);

        var hotspots = new List<StalkMapHotspotDto>();
        if (surface is not null)
        {
            foreach (var block in missed.Blocks)
            {
                if (!TryParseAddr(block.Address, out var rva))
                {
                    hotspots.Add(new StalkMapHotspotDto(block, null, [], [], "unknown", block.PriorityScore));
                    continue;
                }

                var section = surface.SectionAt(rva);
                var nearStr = surface.NearbyStrings(rva);
                var nearImp = surface.NearbyImports(rva);
                var kind = Classify(section, nearStr, nearImp);
                var boost = block.PriorityScore
                            + (nearStr.Any(BinarySurfaceMap.LooksDangerousString) ? 20 : 0)
                            + (nearImp.Count > 0 ? 15 : 0)
                            + (nearStr.Count > 0 ? 8 : 0);

                // Attach surface-aware ideas onto a copy of the block
                var ideas = block.Ideas.ToList();
                if (nearStr.Count > 0)
                {
                    ideas.Insert(0, new MissedFuzzIdeaDto(
                        "surface-string",
                        "Seed toward nearby strings",
                        $"Missed {block.Address} sits near: {string.Join(" · ", nearStr.Take(4))}. " +
                        "Craft inputs that trigger those messages / protocol tokens.",
                        "high",
                        null,
                        "Scare Floor → dictionary tokens from these strings"));
                }
                if (nearImp.Count > 0)
                {
                    ideas.Insert(0, new MissedFuzzIdeaDto(
                        "surface-import",
                        "Reach the import-adjacent path",
                        $"Near imports: {string.Join(", ", nearImp.Take(4))}. " +
                        "Bias length/framed mutators if this is a copy/recv surface.",
                        "high",
                        "randall fuzz -c projects/<proj> --coverage",
                        "Stalking bugs → review hotspot, then revise recipe"));
                }

                var enriched = block with
                {
                    Ideas = ideas,
                    PriorityScore = Math.Min(100, boost),
                    SourceHint = string.IsNullOrWhiteSpace(block.SourceHint)
                        ? kind
                        : $"{block.SourceHint};{kind}",
                    WhyMissed = AppendSurfaceWhy(block.WhyMissed, section, nearStr, nearImp),
                };

                hotspots.Add(new StalkMapHotspotDto(
                    enriched, section, nearStr, nearImp, kind, enriched.PriorityScore));
            }

            hotspots = hotspots
                .OrderByDescending(h => h.BoostedScore)
                .ThenBy(h => h.Block.Address, StringComparer.OrdinalIgnoreCase)
                .Take(limit)
                .ToList();
        }
        else
        {
            hotspots = missed.Blocks.Take(limit)
                .Select(b => new StalkMapHotspotDto(b, null, [], [], "unknown", b.PriorityScore))
                .ToList();
        }

        var interestingImports = (surface?.Imports ?? [])
            .Where(i => i.Interesting)
            .GroupBy(i => $"{i.Library}!{i.Function}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .OrderBy(i => i.Library, StringComparer.OrdinalIgnoreCase)
            .ThenBy(i => i.Function, StringComparer.OrdinalIgnoreCase)
            .Take(40)
            .ToList();

        var hotStrings = (surface?.Strings ?? [])
            .Where(s => BinarySurfaceMap.LooksDangerousString(s.Text) || s.Text.Length >= 8)
            .OrderByDescending(s => BinarySurfaceMap.LooksDangerousString(s.Text))
            .ThenByDescending(s => s.Text.Length)
            .Take(40)
            .ToList();

        var surfaceIdeas = BuildSurfaceIdeas(project, surface, interestingImports, hotStrings, hotspots);
        try
        {
            var host = ExploitSurfaceIdeas.FromLatest(project, repoRoot);
            foreach (var idea in host)
            {
                if (!surfaceIdeas.Any(s => s.Id == idea.Id))
                    surfaceIdeas = surfaceIdeas.Concat([idea]).ToList();
            }
        }
        catch { /* soft */ }

        var format = surface?.Format ?? (resolvedBinary is null ? "missing" : "unknown");
        var summary = surface is null
            ? $"Missed gaps only — no PE/ELF surface (binary {(resolvedBinary ?? "not found")}). " +
              "Pass -c projects/<proj>.yaml or place the target next to the project."
            : $"Stalk map for {System.IO.Path.GetFileName(surface.Path)} ({format}): " +
              $"{surface.Sections.Count} sections · {surface.Imports.Count} imports · {surface.Strings.Count} strings · " +
              $"{hotspots.Count(h => h.NearbyStrings.Count > 0 || h.NearbyImports.Count > 0)} surface-adjacent hotspots.";

        return new StalkMapDto(
            project,
            surface?.Path ?? resolvedBinary,
            format,
            summary,
            missed,
            surface?.Sections ?? [],
            interestingImports,
            hotStrings,
            hotspots,
            surfaceIdeas);
    }

    public static string? ResolveBinary(
        string project,
        string? yamlPath,
        string? binaryPath,
        string repoRoot)
    {
        if (!string.IsNullOrWhiteSpace(binaryPath) && File.Exists(binaryPath))
            return Path.GetFullPath(binaryPath);

        var yaml = yamlPath;
        if (string.IsNullOrWhiteSpace(yaml) || !File.Exists(yaml))
            yaml = FindProjectYaml(repoRoot, project);

        if (!string.IsNullOrWhiteSpace(yaml) && File.Exists(yaml))
        {
            try
            {
                var cfg = ProjectLoader.Load(yaml);
                if (!string.IsNullOrWhiteSpace(cfg.Target.Executable))
                {
                    var declared = ProjectLoader.ResolvePath(yaml, cfg.Target.Executable);
                    var found = ExecutableResolver.FindExisting(declared);
                    if (found is not null)
                        return found;
                }
            }
            catch
            {
                /* fall through */
            }
        }

        // Latest text drcov module matching project name
        var traces = Path.Combine(repoRoot, "data", "corpus", Sanitize(project), "traces");
        if (Directory.Exists(traces))
        {
            var latest = Directory.EnumerateFiles(traces, "*.log")
                .Select(p => new FileInfo(p))
                .Where(f => f.Exists && f.Length > 0)
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .Select(f => f.FullName)
                .FirstOrDefault();
            if (latest is not null)
            {
                foreach (var mod in DrcovParser.ParseModules(latest))
                {
                    var leaf = Path.GetFileName(mod.Path);
                    if (leaf.Contains(project, StringComparison.OrdinalIgnoreCase) && File.Exists(mod.Path))
                        return mod.Path;
                    if (File.Exists(mod.Path) &&
                        (leaf.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                         !leaf.Contains('.')))
                    {
                        // Prefer first existing non-system module
                        if (!mod.Path.Contains("Windows", StringComparison.OrdinalIgnoreCase) &&
                            !mod.Path.Contains("/lib", StringComparison.OrdinalIgnoreCase))
                            return mod.Path;
                    }
                }
            }
        }

        return null;
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

    private static string Classify(string? section, IReadOnlyList<string> strings, IReadOnlyList<string> imports)
    {
        if (imports.Count > 0) return "import-adjacent";
        if (strings.Count > 0) return "string-adjacent";
        if (section is not null &&
            (section.Contains("data", StringComparison.OrdinalIgnoreCase) ||
             section.Contains("rdata", StringComparison.OrdinalIgnoreCase)))
            return "data";
        if (section is not null && section.Contains("text", StringComparison.OrdinalIgnoreCase))
            return "code";
        return section is null ? "unknown" : "code";
    }

    private static string AppendSurfaceWhy(
        string why,
        string? section,
        IReadOnlyList<string> strings,
        IReadOnlyList<string> imports)
    {
        var bits = new List<string>();
        if (!string.IsNullOrWhiteSpace(section))
            bits.Add($"section {section}");
        if (strings.Count > 0)
            bits.Add("near string(s): " + string.Join(", ", strings.Take(2).Select(s => $"\"{Trim(s, 40)}\"")));
        if (imports.Count > 0)
            bits.Add("near import(s): " + string.Join(", ", imports.Take(2)));
        if (bits.Count == 0)
            return why;
        return why + " · Surface: " + string.Join("; ", bits);
    }

    private static IReadOnlyList<MissedFuzzIdeaDto> BuildSurfaceIdeas(
        string project,
        BinarySurfaceMap? surface,
        IReadOnlyList<BinaryImportDto> imports,
        IReadOnlyList<BinaryStringDto> hotStrings,
        IReadOnlyList<StalkMapHotspotDto> hotspots)
    {
        var ideas = new List<MissedFuzzIdeaDto>();
        if (surface is null)
        {
            ideas.Add(new(
                "map-binary",
                "Point Randall at the target binary",
                "Stalk map needs the EXE/ELF to extract strings/imports. Use -c projects/<proj>.yaml or --binary path.",
                "high",
                $"randall stalk map -p {project} -c projects/{project}.yaml",
                "Stalking bugs → Stalk map (set project with a resolvable target.executable)"));
            return ideas;
        }

        if (imports.Count > 0)
        {
            var sample = string.Join(", ", imports.Take(6).Select(i => i.Function));
            ideas.Add(new(
                "map-imports",
                "Bias mutators toward copy/recv imports",
                $"Binary imports interesting APIs: {sample}. Prefer length havoc, framed mutators, and oversized bodies.",
                "high",
                "randall fuzz -c projects/<proj> --coverage",
                "Scare Floor → havoc + interesting + dictionary"));
        }

        if (hotStrings.Count > 0)
        {
            var toks = hotStrings.Take(5).Select(s => Trim(s.Text, 32));
            ideas.Add(new(
                "map-strings",
                "Add surface strings to the dictionary",
                $"Hot strings in the binary: {string.Join(" · ", toks)}. Drop tokens into the project dictionary / Scare Floor.",
                "high",
                null,
                "Scare Floor → dictionary"));
        }

        var adj = hotspots.Count(h => h.SurfaceKind is "string-adjacent" or "import-adjacent");
        if (adj > 0)
        {
            ideas.Add(new(
                "map-hotspots",
                "Fuzz the surface-adjacent missed blocks first",
                $"{adj} missed hotspot(s) sit near strings or dangerous imports — highest ROI before deep Ghidra work.",
                "high",
                $"randall stalk map -p {project}",
                "Stalking bugs → Stalk map hotspots"));
        }

        ideas.Add(new(
            "map-ghidra",
            "Deep-dive hotspots in Ghidra when needed",
            "Randall owns the stalk map; open Ghidra only for hotspots you cannot reach after revising seeds/dicts.",
            "medium",
            $"randall stalk ghidra-pack -p {project}",
            "Stalking bugs → Ghidra export"));

        return ideas;
    }

    private static string Trim(string s, int max) =>
        s.Length <= max ? s : s[..(max - 1)] + "…";

    private static bool TryParseAddr(string addr, out ulong rva)
    {
        rva = 0;
        var s = addr.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            s = s[2..];
        return ulong.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out rva);
    }

    private static string Sanitize(string name)
    {
        foreach (var c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return name;
    }
}
