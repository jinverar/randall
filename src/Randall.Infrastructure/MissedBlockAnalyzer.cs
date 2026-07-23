using System.Globalization;
using Randall.Contracts;
using Randall.Infrastructure.ExploitSurface;

namespace Randall.Infrastructure;

/// <summary>
/// Dynapstalker-style missed-block analysis: you cannot find bugs in code you do not execute.
/// Compares hit coverage (layers + corpus edges) against an optional BB inventory, or falls
/// back to relative gaps (baseline-only, sparse modules, session-graph unexplored forks).
/// </summary>
public static class MissedBlockAnalyzer
{
    public static string InventoryPath(string project, string? repoRoot = null) =>
        Path.Combine(StalkCampaignStore.ProjectDir(project, repoRoot), "inventory.blocks.txt");

    public static StalkInventoryImportResultDto ImportInventory(
        string project,
        string sourcePath,
        string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(project))
            throw new ArgumentException("project required");
        if (string.IsNullOrWhiteSpace(sourcePath) || !File.Exists(sourcePath))
            throw new FileNotFoundException("inventory source not found", sourcePath);

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var edges = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (sourcePath.EndsWith(".log", StringComparison.OrdinalIgnoreCase) ||
            Path.GetFileName(sourcePath).Contains("drcov", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var e in DrcovParser.ParseEdges(sourcePath))
                edges.Add(e);
        }
        else
        {
            foreach (var line in File.ReadLines(sourcePath))
            {
                var edge = NormalizeEdgeLine(line);
                if (edge is not null)
                    edges.Add(edge);
            }
        }

        if (edges.Count == 0)
            throw new InvalidOperationException("No basic-block edges found in inventory source.");

        var dest = InventoryPath(project, repoRoot);
        Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
        File.WriteAllLines(dest, edges.OrderBy(e => e, StringComparer.OrdinalIgnoreCase));
        return new StalkInventoryImportResultDto(project, sourcePath, edges.Count, dest);
    }

    public static StalkMissedReportDto Analyze(
        string project,
        string? repoRoot = null,
        int limit = 80,
        FuzzSessionStatusDto? liveStatus = null)
    {
        if (string.IsNullOrWhiteSpace(project))
            throw new ArgumentException("project required");

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        limit = Math.Clamp(limit, 1, 400);

        var layers = StalkCampaignStore.ListLayers(project, repoRoot);
        var inventory = LoadInventory(project, repoRoot);
        var hit = LoadHitUnion(project, layers, repoRoot);
        var invPath = inventory.Count > 0 ? InventoryPath(project, repoRoot) : null;

        var missed = new List<StalkMissedBlockDto>();

        string mode;
        if (inventory.Count > 0)
        {
            mode = "inventory";
            foreach (var edge in inventory)
            {
                if (hit.Contains(edge))
                    continue;
                missed.Add(BuildNeverHit(edge, hit));
            }
        }
        else
        {
            mode = layers.Count == 0 && hit.Count == 0 ? "empty" : "relative";
            missed.AddRange(BuildBaselineOnly(layers, repoRoot));
            missed.AddRange(BuildModuleSparse(layers, repoRoot));
            missed.AddRange(BuildFrontierGaps(hit));
        }

        missed.AddRange(BuildSessionUnexplored(project, liveStatus));

        // De-dupe by edge key, keep highest priority
        missed = missed
            .GroupBy(m => m.EdgeKey, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(x => x.PriorityScore).First())
            .OrderByDescending(m => m.PriorityScore)
            .ThenBy(m => m.Module, StringComparer.OrdinalIgnoreCase)
            .ThenBy(m => m.Address, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var categories = missed
            .GroupBy(m => m.Category)
            .Select(g => new StalkMissedCategoryDto(
                g.Key,
                CategoryLabel(g.Key),
                g.Count(),
                CategoryDescription(g.Key)))
            .OrderByDescending(c => c.Count)
            .ToList();

        var topIdeas = RankIdeas(missed.SelectMany(m => m.Ideas).ToList(), 12);
        var shown = missed.Take(limit).ToList();

        var summary = mode switch
        {
            "empty" => "No coverage layers or corpus edges yet — record a baseline under drcov, then fuzz and compare.",
            "inventory" =>
                $"{shown.Count} of {missed.Count} never-hit blocks vs inventory ({inventory.Count} known · {hit.Count} hit).",
            _ =>
                $"{shown.Count} of {missed.Count} relative gaps (no full BB inventory — import IDA/Ghidra/drcov edges for true never-hit).",
        };

        var hint = mode switch
        {
            "empty" =>
                "PDF loop: drrun -t drcov -dump_text (baseline) → again under fuzzer → IDC colors in IDA → white=missed → revise → remeasure.",
            "inventory" =>
                "Inventory never-hit ≈ IDA white blocks. Export IDC (oldest first), inspect string/memcpy/error paths, apply fuzz ideas, remeasure with a new color.",
            _ =>
                "Relative gaps approximate the PDF without IDA. True white blocks = binary CFG minus hit colors — export IDC to IDA, or: " +
                "randall stalk inventory -p " + project + " --import <blocks-or-drcov>. " +
                "One-shot: randall stalk dynapstalker <drcov.log> <exe> <out.idc>",
        };

        // Always surface the PDF "interesting surface" ideas when we have any gaps.
        if (missed.Count > 0)
        {
            foreach (var idea in PdfInterestingSurfaceIdeas())
            {
                if (!topIdeas.Any(t => t.Id == idea.Id))
                    topIdeas = topIdeas.Concat([idea]).ToList();
            }
            topIdeas = RankIdeas(topIdeas.ToList(), 12);
        }

        // Fold in Exploit Surface host ideas (sideload / injection / listen).
        try
        {
            var hostIdeas = ExploitSurfaceIdeas.FromLatest(project, repoRoot);
            foreach (var idea in hostIdeas)
            {
                if (!topIdeas.Any(t => t.Id == idea.Id))
                    topIdeas = topIdeas.Concat([idea]).ToList();
            }
            topIdeas = RankIdeas(topIdeas.ToList(), 14);
        }
        catch { /* soft */ }

        return new StalkMissedReportDto(
            project,
            mode,
            summary,
            inventory.Count,
            hit.Count,
            missed.Count,
            categories,
            shown,
            topIdeas,
            hint,
            invPath);
    }

    private static HashSet<string> LoadInventory(string project, string repoRoot)
    {
        var path = InventoryPath(project, repoRoot);
        if (!File.Exists(path))
            return [];
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in File.ReadLines(path))
        {
            var edge = NormalizeEdgeLine(line);
            if (edge is not null)
                set.Add(edge);
        }
        return set;
    }

    private static HashSet<string> LoadHitUnion(
        string project,
        IReadOnlyList<StalkLayerDto> layers,
        string repoRoot)
    {
        var hit = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var layer in layers)
            hit.UnionWith(StalkCampaignStore.LoadEdges(project, layer.Id, repoRoot));

        var corpusEdges = Path.Combine(repoRoot, "data", "corpus", Sanitize(project), "edges.txt");
        if (File.Exists(corpusEdges))
        {
            foreach (var line in File.ReadLines(corpusEdges))
            {
                var edge = NormalizeEdgeLine(line);
                if (edge is not null)
                    hit.Add(edge);
            }
        }

        return hit;
    }

    private static StalkMissedBlockDto BuildNeverHit(string edge, HashSet<string> hit)
    {
        var (module, addr, _) = SplitEdge(edge);
        var nearby = FindNearbyHit(hit, module, addr);
        var ideas = new List<MissedFuzzIdeaDto>
        {
            Idea("seed-near", "Seed traffic near this module",
                $"Block {addr} in module {module} never executed. Craft seeds that exercise the same DLL/EXE paths (valid protocol shells, file containers, or handlers).",
                "high",
                "randall fuzz -c projects/<proj> --coverage",
                "Scare Floor → add seeds / dictionary tokens for this surface"),
            Idea("export-colors", "Color-code in IDA/Ghidra",
                "Export hit layers as IDC/Ghidra colors, then inspect this white block's predecessors (cmp/test/jz) for the gate your fuzzer fails.",
                "medium",
                "randall stalk export -p <project> --format idc",
                "Stalking bugs → IDA IDC / Ghidra export"),
        };

        ideas.Insert(0, Idea("interesting-surface", "Hunt string / memcpy surfaces (PDF)",
            "In IDA, prefer white/missed blocks near strcpy/strcat/sprintf, rep movs*, or manual copy loops — those are high-value for exploitable bugs once reached.",
            "high",
            null,
            "IDA: search for rep movs / string APIs in still-white regions"));

        if (LooksStringy(module, addr))
        {
            ideas.Insert(0, Idea("len-havoc", "Length / memcpy surface",
                "Module naming suggests CRT/string handling — bias length fields, overflow dictionaries, and framed mutators.",
                "high",
                "randall fuzz -c projects/<proj> --profile fuzzier",
                "Scare Floor → enable havoc + length-aware mutators"));
        }

        if (nearby is not null)
        {
            ideas.Add(Idea("flip-branch", "Flip the branch that skips this block",
                $"A hit block sits nearby ({nearby}). The miss is likely a not-taken conditional — mutate comparison operands and flags that gate this edge.",
                "high",
                null,
                "Inspect cmp/test before the gap; add dictionary values that invert the branch"));
        }

        var score = 70 + (nearby is null ? 0 : 15) + (LooksStringy(module, addr) ? 10 : 0);
        return new StalkMissedBlockDto(
            edge, addr, module, "never-hit",
            nearby is null
                ? "Present in the BB inventory but never seen in any stalk layer or corpus edges."
                : $"Never hit; nearest executed block in this module is {nearby}.",
            ideas, score, nearby, null, "inventory");
    }

    private static IEnumerable<StalkMissedBlockDto> BuildBaselineOnly(
        IReadOnlyList<StalkLayerDto> layers,
        string repoRoot)
    {
        var baselineLayers = layers.Where(IsBaselineTag).ToList();
        var fuzzLayers = layers.Where(l => !IsBaselineTag(l)).ToList();
        if (baselineLayers.Count == 0 || fuzzLayers.Count == 0)
            yield break;

        var baseline = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var l in baselineLayers)
            baseline.UnionWith(StalkCampaignStore.LoadEdges(l.Project, l.Id, repoRoot));

        var fuzzed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var l in fuzzLayers)
            fuzzed.UnionWith(StalkCampaignStore.LoadEdges(l.Project, l.Id, repoRoot));

        var emitted = 0;
        foreach (var edge in baseline.OrderBy(e => e))
        {
            if (fuzzed.Contains(edge))
                continue;
            var (module, addr, _) = SplitEdge(edge);
            var ideas = new List<MissedFuzzIdeaDto>
            {
                Idea("replay-baseline", "Replay happy-path as seeds",
                "This block ran during normal use but no fuzz layer revisited it. Capture baseline requests/files into the corpus and keep a low-havoc lane so the scheduler still exercises them.",
                "high",
                "randall stalk layers -p <project>  # confirm baseline vs fuzzed",
                "Stalking bugs → From corpus edges after saving happy-path inputs"),
                Idea("profile-basic", "Keep a basic profile lane",
                "Over-aggressive mutators can strand the fuzzer off the normal CFG. Run a parallel basic/fuzz profile that preserves valid shells.",
                "medium",
                "randall stalk bench -c projects/<proj> --profiles basic,fuzz,fuzzier",
                "Fuzz → profile basic alongside fuzzier"),
            };
            yield return new StalkMissedBlockDto(
                edge, addr, module, "baseline-only",
                "Hit during baseline (normal use) but absent from later fuzz/fuzzier/crash layers.",
                ideas, 85, null, null, "layer-compare");
            if (++emitted >= 200)
                yield break;
        }
    }

    private static IEnumerable<StalkMissedBlockDto> BuildModuleSparse(
        IReadOnlyList<StalkLayerDto> layers,
        string repoRoot)
    {
        var baselineLayers = layers.Where(IsBaselineTag).ToList();
        var fuzzLayers = layers.Where(l => !IsBaselineTag(l)).ToList();
        if (baselineLayers.Count == 0 || fuzzLayers.Count == 0)
            yield break;

        var baseByMod = CountByModule(baselineLayers, repoRoot);
        var fuzzByMod = CountByModule(fuzzLayers, repoRoot);

        foreach (var (module, baseCount) in baseByMod.OrderByDescending(kv => kv.Value))
        {
            if (baseCount < 8)
                continue;
            fuzzByMod.TryGetValue(module, out var fuzzCount);
            var ratio = fuzzCount / (double)baseCount;
            if (ratio >= 0.35)
                continue;

            var key = $"module-sparse:{module}";
            var ideas = new List<MissedFuzzIdeaDto>
            {
                Idea("module-focus", $"Focus seeds on module {module}",
                    $"Baseline touched {baseCount} blocks in module {module}; fuzz layers only {fuzzCount} ({ratio:P0}). The fuzzer is barely stalking this component.",
                    "high",
                    null,
                    "Add dictionaries / session commands that enter this module; prefer coverage-guided power schedule"),
                Idea("coverage-tcp", "Keep coverage attached",
                    "Ensure fuzz.coverageGuided + DynamoRIO (or native stalk) stay on so novel edges in this module earn corpus energy.",
                    "medium",
                    "randall doctor -c projects/<proj>",
                    "Fuzz → coverage guided checked"),
            };

            yield return new StalkMissedBlockDto(
                key,
                "module",
                module,
                "module-sparse",
                $"Sparse vs baseline: {fuzzCount}/{baseCount} blocks revisited by fuzz layers.",
                ideas,
                90,
                null,
                null,
                "module-ratio");
        }
    }

    private static IEnumerable<StalkMissedBlockDto> BuildFrontierGaps(HashSet<string> hit)
    {
        // Per module, sort RVAs; emit a gap marker when consecutive hits leave a large hole.
        var byMod = new Dictionary<string, List<(ulong Rva, string Edge, string Addr)>>(StringComparer.OrdinalIgnoreCase);
        foreach (var edge in hit)
        {
            var (module, addr, _) = SplitEdge(edge);
            if (!TryParseAddr(addr, out var rva))
                continue;
            if (!byMod.TryGetValue(module, out var list))
            {
                list = [];
                byMod[module] = list;
            }
            list.Add((rva, edge, addr));
        }

        foreach (var (module, list) in byMod)
        {
            var ordered = list.DistinctBy(x => x.Rva).OrderBy(x => x.Rva).ToList();
            for (var i = 1; i < ordered.Count; i++)
            {
                var gap = ordered[i].Rva - ordered[i - 1].Rva;
                // Typical BB ~8–40 bytes; a hole ≥ 0x80 suggests skipped region(s).
                if (gap < 0x80 || gap > 0x4000)
                    continue;

                var mid = ordered[i - 1].Rva + (gap / 2);
                var addr = $"0x{mid:x8}";
                var key = $"{module}:{addr}:gap";
                var ideas = new List<MissedFuzzIdeaDto>
                {
                    Idea("branch-flip", "Probe the untaken branch",
                        $"Coverage jumps from {ordered[i - 1].Addr} to {ordered[i].Addr} (gap 0x{gap:x}). Likely skipped basic blocks — mutate the predicate between them.",
                        "high",
                        null,
                        "IDA/Ghidra: jump to the earlier block, find jz/jnz, invent inputs that invert it"),
                    Idea("dict-boundary", "Boundary / enum dictionary",
                        "Gaps often hide error paths, magic checks, or length gates. Add boundary integers and protocol enums to the dictionary.",
                        "medium",
                        "randall ai seed -c projects/<proj> --dry-run",
                        "Scare Floor → dictionary / AI seed recipe"),
                };

                yield return new StalkMissedBlockDto(
                    key, addr, module, "frontier-gap",
                    $"Hit blocks surround a 0x{gap:x}-byte hole — probable missed region between executed code.",
                    ideas, 75, ordered[i - 1].Addr, null, "frontier");

                // Cap noise per module
                if (list.Count > 0 && ordered.Count > 20 && i > ordered.Count / 2)
                    break;
            }
        }
    }

    private static IEnumerable<StalkMissedBlockDto> BuildSessionUnexplored(
        string project,
        FuzzSessionStatusDto? liveStatus)
    {
        StalkDashboardDto? dash;
        try
        {
            dash = StalkDashboard.ForProject(project, liveStatus, null);
        }
        catch
        {
            yield break;
        }

        if (dash is null)
            yield break;

        foreach (var block in dash.Blocks.Where(b =>
                     string.Equals(b.Kind, "unexplored", StringComparison.OrdinalIgnoreCase)))
        {
            var cmd = block.Command ?? block.Label;
            var ideas = new List<MissedFuzzIdeaDto>
            {
                Idea("session-cmd", $"Exercise session command '{cmd}'",
                    "This handler/fork sits off the crash spine — the protocol graph knows about it, but fuzz inputs never took that edge.",
                    "high",
                    null,
                    "Session graph / Scare Floor → add a step that sends this command after the right preamble"),
            };
            if (!string.IsNullOrWhiteSpace(block.ExpectResponse))
            {
                ideas.Add(Idea("expect-resp", "Satisfy the expected response gate",
                    $"Handler expects something like '{block.ExpectResponse}'. Wrong status/banner may skip the interesting body parser.",
                    "medium",
                    null,
                    "Enable cookie jar / auth preamble; add response-class oracles"));
            }

            if (!string.IsNullOrWhiteSpace(block.Mutator))
            {
                ideas.Add(Idea("mutator", $"Bias mutator '{block.Mutator}'",
                    "Recipe already names a mutator for this fork — weight it higher or lock a campaign lane to it.",
                    "medium",
                    null,
                    "Scare Floor → mutator checks"));
            }

            var edge = string.IsNullOrWhiteSpace(block.Address)
                ? $"session:{block.Id}"
                : $"{block.Module ?? "session"}:{block.Address}:0";

            yield return new StalkMissedBlockDto(
                edge,
                string.IsNullOrWhiteSpace(block.Address) ? "session" : block.Address,
                block.Module ?? "session",
                "session-unexplored",
                string.IsNullOrWhiteSpace(block.Detail)
                    ? $"Session-graph fork '{cmd}' is known but not on the exercised path."
                    : block.Detail,
                ideas,
                80,
                null,
                cmd,
                "session-graph");
        }
    }

    private static Dictionary<string, int> CountByModule(IReadOnlyList<StalkLayerDto> layers, string repoRoot)
    {
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var layer in layers)
        {
            foreach (var edge in StalkCampaignStore.LoadEdges(layer.Project, layer.Id, repoRoot))
            {
                var (module, _, _) = SplitEdge(edge);
                counts.TryGetValue(module, out var n);
                counts[module] = n + 1;
            }
        }
        return counts;
    }

    private static bool IsBaselineTag(StalkLayerDto layer) =>
        layer.Tag.Contains("base", StringComparison.OrdinalIgnoreCase);

    private static MissedFuzzIdeaDto Idea(
        string id, string title, string detail, string priority,
        string? cli = null, string? ui = null) =>
        new(id, title, detail, priority, cli, ui);

    private static IReadOnlyList<MissedFuzzIdeaDto> RankIdeas(List<MissedFuzzIdeaDto> ideas, int limit)
    {
        static int Rank(string p) => p switch
        {
            "high" => 3,
            "medium" => 2,
            _ => 1,
        };

        return ideas
            .GroupBy(i => i.Id, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(x => Rank(x.Priority)).First())
            .OrderByDescending(i => Rank(i.Priority))
            .ThenBy(i => i.Title, StringComparer.OrdinalIgnoreCase)
            .Take(limit)
            .ToList();
    }

    private static string CategoryLabel(string id) => id switch
    {
        "never-hit" => "Never hit (inventory)",
        "baseline-only" => "Baseline only",
        "module-sparse" => "Sparse module",
        "session-unexplored" => "Session unexplored",
        "frontier-gap" => "Frontier gap",
        _ => id,
    };

    private static string CategoryDescription(string id) => id switch
    {
        "never-hit" => "In the BB inventory but absent from all campaign hits — classic Dynapstalker / IDA white blocks.",
        "baseline-only" => "Reached during normal use (PDF yellow), then abandoned by fuzz layers (not re-colored green).",
        "module-sparse" => "Whole modules barely revisited after baseline.",
        "session-unexplored" => "Protocol/session forks that exist in the graph but were not taken.",
        "frontier-gap" => "Address holes between hit blocks — likely skipped branches (white islands between colored BBs).",
        _ => "",
    };

    private static IEnumerable<MissedFuzzIdeaDto> PdfInterestingSurfaceIdeas() =>
    [
        Idea("pdf-white", "Treat IDA white / Ghidra plain as ground truth",
            "After loading baseline (yellow) then fuzzed (green) scripts, remaining uncolored blocks are code neither pass executed — that is the PDF definition of missed.",
            "high",
            "randall stalk dynapstalker <baseline.log> <exe> base.idc --color 0x00ffff   # or out.py --format ghidra",
            "Stalking bugs → IDA IDC / Ghidra export (oldest first)"),
        Idea("pdf-revise", "Revise fuzzer, then remeasure with a new color",
            "Change seeds/dicts/mutators to reach interesting white blocks (string copies, error handlers, auth gates), run again under drcov, export a third color for the improved round.",
            "high",
            "randall stalk missed -p <project>",
            "Scare Floor → new recipe → Campaign → record fuzzier layer"),
        Idea("pdf-error-paths", "Exercise non-happy HTTP/protocol statuses",
            "PDF baseline includes 404 / non-200 responses. If your baseline was only success paths, record a richer baseline (errors, auth fail, oversized headers) before judging the fuzzer.",
            "medium",
            null,
            "Manual browse / client: trigger 404s and errors under coverage, then re-record baseline"),
    ];

    private static string? FindNearbyHit(HashSet<string> hit, string module, string addr)
    {
        if (!TryParseAddr(addr, out var target))
            return null;
        string? best = null;
        var bestDist = ulong.MaxValue;
        foreach (var edge in hit)
        {
            var (mod, a, _) = SplitEdge(edge);
            if (!string.Equals(mod, module, StringComparison.OrdinalIgnoreCase))
                continue;
            if (!TryParseAddr(a, out var rva))
                continue;
            var dist = target > rva ? target - rva : rva - target;
            if (dist > 0 && dist < bestDist && dist < 0x2000)
            {
                bestDist = dist;
                best = a;
            }
        }
        return best;
    }

    private static bool LooksStringy(string module, string addr) =>
        module.Contains("crt", StringComparison.OrdinalIgnoreCase) ||
        module.Contains("ucrt", StringComparison.OrdinalIgnoreCase) ||
        module.Contains("msvcrt", StringComparison.OrdinalIgnoreCase) ||
        addr.Contains("strcpy", StringComparison.OrdinalIgnoreCase);

    private static string? NormalizeEdgeLine(string? line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return null;
        var t = line.Trim();
        if (t.StartsWith('#') || t.StartsWith("//"))
            return null;
        // Already module:start:size
        if (t.Contains(':'))
            return t;
        // Bare 0xRVA → unknown module
        if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return $"?:{t}:0";
        return t;
    }

    private static (string Module, string Address, string Size) SplitEdge(string edge)
    {
        var parts = edge.Split(':');
        if (parts.Length >= 3)
        {
            var addr = parts[1].StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? parts[1] : $"0x{parts[1]}";
            return (parts[0], addr, parts[2]);
        }
        if (parts.Length == 2)
        {
            var addr = parts[1].StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? parts[1] : $"0x{parts[1]}";
            return (parts[0], addr, "0");
        }
        return ("?", edge, "0");
    }

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
