using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Layered stalk campaigns — baseline → fuzzed → fuzzier → crash compares (Dynapstalker / PaiMei workflow).
/// Persisted under data/stalk/{project}/.
/// </summary>
public static class StalkCampaignStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
    };

    private static readonly string[] DefaultColors =
    [
        "0x00FFFF", // yellow-ish cyan baseline (IDA BGR)
        "0x00FF00", // green fuzzed
        "0x0080FF", // orange fuzzier
        "0xFF00FF", // magenta
        "0x00A5FF", // orange deep
        "0xFF0000", // blue (IDA BGR) — later layers
    ];

    public static string RootDir(string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        return Path.Combine(repoRoot, "data", "stalk");
    }

    public static string ProjectDir(string project, string? repoRoot = null) =>
        Path.Combine(RootDir(repoRoot), Sanitize(project));

    public static StalkCampaignDto GetCampaign(string project, string? repoRoot = null)
    {
        var dir = ProjectDir(project, repoRoot);
        Directory.CreateDirectory(dir);
        var layers = ListLayers(project, repoRoot);
        var compare = layers.Count >= 1
            ? Compare(project, layers.Select(l => l.Id).ToList(), repoRoot)
            : null;
        return new StalkCampaignDto(project, layers, compare);
    }

    public static IReadOnlyList<StalkLayerDto> ListLayers(string project, string? repoRoot = null)
    {
        var dir = ProjectDir(project, repoRoot);
        if (!Directory.Exists(dir))
            return [];

        var list = new List<StalkLayerDto>();
        foreach (var metaPath in Directory.EnumerateFiles(dir, "layer-*.json").OrderBy(p => p))
        {
            try
            {
                var layer = JsonSerializer.Deserialize<StalkLayerDto>(File.ReadAllText(metaPath), JsonOptions);
                if (layer is not null)
                    list.Add(layer);
            }
            catch
            {
                /* skip corrupt */
            }
        }

        return list;
    }

    public static StalkLayerDto AddLayer(StalkLayerCreateRequest request, string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(request.Project))
            throw new ArgumentException("project required");
        if (string.IsNullOrWhiteSpace(request.Tag))
            throw new ArgumentException("tag required");

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var dir = ProjectDir(request.Project, repoRoot);
        Directory.CreateDirectory(dir);

        var edges = ResolveEdges(request, repoRoot);
        var id = $"{DateTime.UtcNow:yyyyMMdd_HHmmss}_{Guid.NewGuid():N}"[..24];
        var existing = ListLayers(request.Project, repoRoot);
        var color = string.IsNullOrWhiteSpace(request.ColorHex)
            ? DefaultColors[existing.Count % DefaultColors.Length]
            : request.ColorHex!;
        var label = string.IsNullOrWhiteSpace(request.Label)
            ? $"{request.Tag} #{existing.Count + 1}"
            : request.Label!;

        var edgesPath = Path.Combine(dir, $"layer-{id}.edges.txt");
        File.WriteAllLines(edgesPath, edges.OrderBy(e => e, StringComparer.OrdinalIgnoreCase));

        var source = request.DrcovPath ?? request.EdgesPath ?? request.CrashId;
        if (!string.IsNullOrWhiteSpace(request.DrcovPath) && File.Exists(request.DrcovPath))
        {
            var copy = Path.Combine(dir, $"layer-{id}.drcov.log");
            File.Copy(request.DrcovPath, copy, overwrite: true);
            source = copy;
        }

        var layer = new StalkLayerDto(
            id,
            request.Project,
            request.Tag.Trim().ToLowerInvariant(),
            label,
            color,
            DateTimeOffset.UtcNow,
            edges.Count,
            source,
            request.CrashId,
            request.Notes);

        File.WriteAllText(Path.Combine(dir, $"layer-{id}.json"), JsonSerializer.Serialize(layer, JsonOptions));
        return layer;
    }

    public static bool DeleteLayer(string project, string layerId, string? repoRoot = null)
    {
        var dir = ProjectDir(project, repoRoot);
        var meta = Path.Combine(dir, $"layer-{layerId}.json");
        if (!File.Exists(meta))
            return false;
        File.Delete(meta);
        foreach (var pattern in new[] { $"layer-{layerId}.edges.txt", $"layer-{layerId}.drcov.log" })
        {
            var p = Path.Combine(dir, pattern);
            if (File.Exists(p))
                File.Delete(p);
        }

        return true;
    }

    public static StalkCompareDto Compare(string project, IReadOnlyList<string> layerIds, string? repoRoot = null)
    {
        var layers = ListLayers(project, repoRoot)
            .Where(l => layerIds.Count == 0 || layerIds.Contains(l.Id, StringComparer.OrdinalIgnoreCase))
            .OrderBy(l => l.CreatedAt)
            .ToList();

        if (layers.Count == 0)
            return new StalkCompareDto(project, [], 0, 0, [], []);

        var sets = layers.Select(l => (Layer: l, Edges: LoadEdges(project, l.Id, repoRoot))).ToList();
        var union = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in sets)
            union.UnionWith(s.Edges);

        var shared = new HashSet<string>(sets[0].Edges, StringComparer.OrdinalIgnoreCase);
        foreach (var s in sets.Skip(1))
            shared.IntersectWith(s.Edges);

        var previous = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var deltas = new List<StalkLayerDeltaDto>();
        foreach (var s in sets)
        {
            var unique = s.Edges.Except(sets.Where(x => x.Layer.Id != s.Layer.Id).SelectMany(x => x.Edges), StringComparer.OrdinalIgnoreCase).Count();
            var novel = s.Edges.Count(e => !previous.Contains(e));
            deltas.Add(new StalkLayerDeltaDto(s.Layer.Id, s.Layer.Tag, unique, novel));
            previous.UnionWith(s.Edges);
        }

        var blocks = new List<StalkBlockHitDto>();
        foreach (var edge in union.OrderBy(e => e))
        {
            var hitLayers = sets.Where(s => s.Edges.Contains(edge)).Select(s => s.Layer).ToList();
            var first = hitLayers[0];
            var (module, addr) = SplitEdge(edge);
            var kind = "shared";
            if (hitLayers.Count == 1 && first.Tag.Contains("base", StringComparison.OrdinalIgnoreCase))
                kind = "baseline";
            else if (hitLayers.Count == 1)
                kind = "novel";
            else if (first.Tag.Contains("crash", StringComparison.OrdinalIgnoreCase) || first.CrashId is not null)
                kind = "crash";
            else if (hitLayers.Any(l => l.Tag.Contains("crash", StringComparison.OrdinalIgnoreCase)))
                kind = "crash";
            else if (hitLayers[0].Tag.Contains("base", StringComparison.OrdinalIgnoreCase) && hitLayers.Count > 1)
                kind = "shared";
            else if (!hitLayers[0].Tag.Contains("base", StringComparison.OrdinalIgnoreCase))
                kind = "novel";

            // Prefer crash coloring when any crash layer owns the edge uniquely at end
            if (hitLayers.Any(l => l.CrashId is not null || l.Tag.Contains("crash", StringComparison.OrdinalIgnoreCase)))
            {
                var crashLayer = hitLayers.LastOrDefault(l => l.CrashId is not null || l.Tag.Contains("crash", StringComparison.OrdinalIgnoreCase));
                if (crashLayer is not null && hitLayers.Count == 1)
                    kind = "crash";
            }

            blocks.Add(new StalkBlockHitDto(
                addr,
                module,
                kind,
                first.Id,
                first.Tag,
                hitLayers.Select(l => l.Id).ToList()));
        }

        return new StalkCompareDto(
            project,
            layers.Select(l => l.Id).ToList(),
            union.Count,
            shared.Count,
            deltas,
            blocks.Take(400).ToList());
    }

    public static HashSet<string> LoadEdges(string project, string layerId, string? repoRoot = null)
    {
        var path = Path.Combine(ProjectDir(project, repoRoot), $"layer-{layerId}.edges.txt");
        if (!File.Exists(path))
            return [];
        return File.ReadLines(path)
            .Where(l => !string.IsNullOrWhiteSpace(l))
            .Select(l => l.Trim())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    public static StalkWorkspaceDto Workspace(string project, string? repoRoot = null)
    {
        var campaign = GetCampaign(project, repoRoot);
        var tools = ProbeTools(repoRoot);
        var hint = campaign.Layers.Count == 0
            ? "Record a baseline layer (normal use under drcov), then add fuzzed layers and compare."
            : campaign.Layers.Count == 1
                ? "Baseline recorded. Add a fuzzed layer after your next campaign, then compare."
                : "Compare layers, export IDC/Ghidra colors, inspect novel blocks, refine the fuzzer.";
        return new StalkWorkspaceDto(project, campaign, tools, hint);
    }

    public static IReadOnlyList<StalkToolLinkDto> ProbeTools(string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var toolsDir = Path.Combine(repoRoot, "tools");

        bool ExistsOnPath(string name)
        {
            var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (var dir in pathEnv.Split(Path.PathSeparator))
            {
                if (string.IsNullOrWhiteSpace(dir)) continue;
                if (File.Exists(Path.Combine(dir, name)) || File.Exists(Path.Combine(dir, name + ".exe")))
                    return true;
            }
            return File.Exists(Path.Combine(toolsDir, name)) || File.Exists(Path.Combine(toolsDir, name + ".exe"));
        }

        var dr = DynamoRioRunner.Discover();
        var dbg = DebuggerTools.Probe();
        string StatusFor(string id)
        {
            var t = dbg.Tools.FirstOrDefault(x => x.Id == id);
            return t?.Available == true ? "ready" : "missing";
        }

        return
        [
            new("dynamorio", "DynamoRIO drcov", dr.IsAvailable ? "ready" : "missing",
                "Basic-block coverage for local instrumented targets",
                dr.DrrunPath is null ? null : $"\"{dr.DrrunPath}\" -t drcov -dump_text -- <target>"),
            new("scream", "Scream watcher", "ready",
                "Built-in debug-attach → second-chance minidump (debuggerMode: wait)",
                "randall scream watch -p <pid>"),
            new("procdump", "ProcDump", StatusFor("procdump"),
                "Optional -e -ma arm (fuzz.procdumpOnCrash) when Scream is not attached",
                dbg.Tools.FirstOrDefault(t => t.Id == "procdump")?.CommandHint),
            new("windbg-preview", "WinDbg Preview", StatusFor("windbg-preview"),
                "Attach live or open crash dumps (Microsoft Store / WinDbgX)",
                dbg.Tools.FirstOrDefault(t => t.Id == "windbg-preview")?.CommandHint),
            new("windbg", "WinDbg (classic)", StatusFor("windbg"),
                "Attach live or open crash dumps (Windows SDK Debuggers)",
                dbg.Tools.FirstOrDefault(t => t.Id == "windbg")?.CommandHint),
            new("cdb", "cdb", StatusFor("cdb"),
                "Headless attach → dump on break (wait mode fallback)",
                dbg.Tools.FirstOrDefault(t => t.Id == "cdb")?.CommandHint),
            new("procmon", "Process Monitor",
                ProcmonCapture.DiscoverExecutable(repoRoot) is not null ? "ready" : "missing",
                "File/registry/network activity — set fuzz.procmonCapture: true or /api/remote/procmon",
                "Procmon /AcceptEula /Quiet /BackingFile fuzz.pml"),
            new("tcpvcon", "TCPVCon",
                TcpvconCapture.DiscoverExecutable(repoRoot) is not null ? "ready" : "missing",
                "Network connection snapshots — fuzz.tcpvconCapture (tcpvcon/tcpvcon64 from TCPView package)",
                "tcpvcon64 -accepteula -a -c -n [pid]"),
            new("pktmon", "Packet Monitor",
                PktmonCapture.DiscoverExecutable() is not null ? "ready" : "missing",
                "NIC packet ETL bookend — fuzz.pktmonCapture (often needs elevation)",
                "pktmon start --capture --comp nics -f fuzz-pktmon.etl"),
            new("debugview", "DebugView",
                DebugViewCapture.DiscoverExecutable(repoRoot) is not null ? "ready" : "missing",
                "OutputDebugString capture — fuzz.debugViewCapture (Dbgview.exe in tools/ or PATH)",
                "Dbgview /accepteula /t /o /l debugview.log"),
            new("sysinternals-snap", "Sysinternals snapshots",
                SysinternalsToolPaths.FindHandle(repoRoot) is not null ||
                SysinternalsToolPaths.FindListDlls(repoRoot) is not null ||
                SysinternalsToolPaths.FindPsList(repoRoot) is not null
                    ? "ready"
                    : "missing",
                "Handle + ListDLLs + PsList + netstat bookends — fuzz.sysinternalsSnapshots",
                "handle64 -p <pid> · listdlls64 <pid> · pslist <pid>"),
            new("procexp", "Process Explorer", ExistsOnPath("procexp") || ExistsOnPath("procexp64") ? "ready" : "planned",
                "Live process tree, handles, and module view (GUI — not bookended)",
                null),
            new("native-stalk", "Native PC stalk", new NativeStalkRunner().IsAvailable ? "ready" : "missing",
                "Debug-event PC samples → drcov (no DynamoRIO). Coarser than external BB coverage.",
                "fuzz.stalkMode: native | auto"),
            new("remote-agent", "Remote stalk agent", "ready",
                "Same Server on 0.0.0.0 — /api/remote/procmon + /api/remote/tools on the lab box",
                "randall agent --bind 0.0.0.0"),
        ];
    }

    private static HashSet<string> ResolveEdges(StalkLayerCreateRequest request, string repoRoot)
    {
        var edges = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(request.DrcovPath))
        {
            var path = Path.GetFullPath(request.DrcovPath);
            foreach (var e in DrcovParser.ParseEdges(path))
                edges.Add(e);
        }

        if (!string.IsNullOrWhiteSpace(request.EdgesPath) && File.Exists(request.EdgesPath))
        {
            foreach (var line in File.ReadLines(request.EdgesPath))
            {
                if (!string.IsNullOrWhiteSpace(line))
                    edges.Add(line.Trim());
            }
        }

        if (!string.IsNullOrWhiteSpace(request.CrashId) && Guid.TryParse(request.CrashId, out var crashGuid))
        {
            var detail = CrashCatalog.GetDetail(crashGuid, repoRoot);
            var trace = detail?.Sidecar?.TraceCopyPath ?? detail?.Sidecar?.TracePath;
            if (trace is not null)
            {
                foreach (var e in DrcovParser.ParseEdges(trace))
                    edges.Add(e);
            }
        }

        // Convenience: import current corpus edges as a layer when no path given
        if (edges.Count == 0)
        {
            var corpusEdges = Path.Combine(repoRoot, "data", "corpus", request.Project, "edges.txt");
            if (File.Exists(corpusEdges))
            {
                foreach (var line in File.ReadLines(corpusEdges))
                {
                    if (!string.IsNullOrWhiteSpace(line))
                        edges.Add(line.Trim());
                }
            }
        }

        return edges;
    }

    private static (string Module, string Address) SplitEdge(string edge)
    {
        var parts = edge.Split(':');
        if (parts.Length >= 2)
            return (parts[0], parts[1].StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? parts[1] : $"0x{parts[1]}");
        return ("?", edge);
    }

    private static string Sanitize(string name)
    {
        foreach (var c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return name;
    }
}
