using System.Globalization;
using System.Text;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Build a lightweight crash-neighborhood graph from mini-timeline CSVs + crash metadata.
/// Post-process only — see docs/MINI_TIMELINE.md.
/// </summary>
public static class MiniTimelineGraphBuilder
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static string GraphPath(string rootDir, Guid crashId) =>
        GraphPath(rootDir, crashId.ToString("N"));

    public static string GraphPath(string rootDir, string timelineKey) =>
        Path.Combine(MiniTimelineCapture.TimelineDir(rootDir, timelineKey), "graph.json");

    public static string MergedCsvPath(string rootDir, Guid crashId) =>
        MergedCsvPath(rootDir, crashId.ToString("N"));

    public static string MergedCsvPath(string rootDir, string timelineKey) =>
        Path.Combine(MiniTimelineCapture.TimelineDir(rootDir, timelineKey), "merged.csv");

    public static MiniTimelineGraphDto Build(
        string rootDir,
        Guid crashId,
        MiniTimelineSummaryDto summary,
        string? inputPath = null,
        int maxNodesPerSource = 40,
        string? timelineKey = null)
    {
        var nodes = new List<MiniTimelineGraphNodeDto>();
        var edges = new List<MiniTimelineGraphEdgeDto>();
        var key = string.IsNullOrWhiteSpace(timelineKey) ? crashId.ToString("N") : timelineKey!;
        var dir = MiniTimelineCapture.TimelineDir(rootDir, key);

        void AddNode(string id, string kind, string label, params (string k, string v)[] props)
        {
            if (nodes.Any(n => n.Id == id)) return;
            var dict = props.Length == 0
                ? null
                : props.ToDictionary(p => p.k, p => p.v, StringComparer.OrdinalIgnoreCase);
            nodes.Add(new MiniTimelineGraphNodeDto(id, kind, label, dict));
        }

        void AddEdge(string from, string to, string kind, string? label = null)
        {
            edges.Add(new MiniTimelineGraphEdgeDto(from, to, kind, label));
        }

        var crashNode = $"crash:{crashId:N}";
        AddNode(crashNode, "crash", summary.SummaryLine,
            ("windowSeconds", summary.WindowSeconds.ToString(CultureInfo.InvariantCulture)),
            ("anchorUtc", summary.AnchorUtc.ToString("O")));

        if (!string.IsNullOrWhiteSpace(inputPath))
        {
            AddNode("input", "input", Path.GetFileName(inputPath), ("path", inputPath));
            AddEdge("input", crashNode, "crashed_with");
        }

        if (!string.IsNullOrWhiteSpace(summary.TargetExe))
        {
            AddNode("target", "process", Path.GetFileName(summary.TargetExe), ("path", summary.TargetExe));
            AddEdge(crashNode, "target", "in_process");
        }

        IngestCsv(Path.Combine(dir, "evtx.csv"), "evtx", "event",
            preferLabelCols: ["EventId", "Event ID", "Provider", "Map description", "Payload Data1"],
            maxNodesPerSource, AddNode, AddEdge, crashNode, "emitted");

        IngestCsv(Path.Combine(dir, "mft.csv"), "mft", "file",
            preferLabelCols: ["ParentPath", "FileName", "Extension", "Map description"],
            maxNodesPerSource, AddNode, AddEdge, crashNode, "filesystem");

        IngestCsv(Path.Combine(dir, "procmon.csv"), "procmon", "op",
            preferLabelCols: ["Operation", "Path", "Detail", "Process Name"],
            maxNodesPerSource, AddNode, AddEdge, crashNode, "observed");

        IngestCsv(Path.Combine(dir, "prefetch.csv"), "prefetch", "execution",
            preferLabelCols: ["ExecutableName", "SourceFilename", "RunCount"],
            maxNodesPerSource, AddNode, AddEdge, crashNode, "prefetch");

        IngestCsv(Path.Combine(dir, "appcompat.csv"), "appcompat", "shim",
            preferLabelCols: ["Path", "ProgramName", "Executed"],
            maxNodesPerSource, AddNode, AddEdge, crashNode, "shimcache");

        var werDir = Path.Combine(dir, "wer");
        if (Directory.Exists(werDir))
        {
            foreach (var wer in Directory.EnumerateFiles(werDir, "*.wer").Take(10))
            {
                var id = "wer:" + Path.GetFileNameWithoutExtension(wer);
                AddNode(id, "wer", Path.GetFileName(wer), ("path", wer));
                AddEdge(crashNode, id, "wer_report");
            }
        }

        if (!string.IsNullOrWhiteSpace(summary.BstringsPath))
        {
            AddNode("bstrings", "strings", "bstrings.txt", ("path", summary.BstringsPath));
            AddEdge(crashNode, "bstrings", "strings_from");
        }

        return new MiniTimelineGraphDto(
            crashId.ToString("N"),
            summary.Project,
            summary.AnchorUtc,
            nodes,
            edges,
            $"nodes={nodes.Count} edges={edges.Count}");
    }

    public static string Write(
        string rootDir,
        Guid crashId,
        MiniTimelineSummaryDto summary,
        string? inputPath = null,
        string? timelineKey = null)
    {
        var key = string.IsNullOrWhiteSpace(timelineKey) ? crashId.ToString("N") : timelineKey!;
        var graph = Build(rootDir, crashId, summary, inputPath, timelineKey: key);
        var path = GraphPath(rootDir, key);
        File.WriteAllText(path, JsonSerializer.Serialize(graph, JsonOpts));
        TryWriteMergedCsv(rootDir, key);
        return path;
    }

    public static MiniTimelineGraphDto? TryRead(string rootDir, Guid crashId) =>
        TryRead(rootDir, crashId.ToString("N"));

    public static MiniTimelineGraphDto? TryRead(string rootDir, string timelineKey)
    {
        var path = GraphPath(rootDir, timelineKey);
        if (!File.Exists(path)) return null;
        try
        {
            return JsonSerializer.Deserialize<MiniTimelineGraphDto>(File.ReadAllText(path), JsonOpts);
        }
        catch
        {
            return null;
        }
    }

    private static void TryWriteMergedCsv(string rootDir, string timelineKey)
    {
        var dir = MiniTimelineCapture.TimelineDir(rootDir, timelineKey);
        var dest = MergedCsvPath(rootDir, timelineKey);
        var sources = new (string Name, string File)[]
        {
            ("evtx", "evtx.csv"),
            ("mft", "mft.csv"),
            ("procmon", "procmon.csv"),
            ("prefetch", "prefetch.csv"),
            ("amcache", "amcache.csv"),
            ("appcompat", "appcompat.csv"),
        };

        using var writer = new StreamWriter(dest, false, Encoding.UTF8);
        writer.WriteLine("Source,Row");
        foreach (var (name, file) in sources)
        {
            var path = Path.Combine(dir, file);
            if (!File.Exists(path)) continue;
            var lines = File.ReadAllLines(path);
            for (var i = 1; i < lines.Length && i <= 5000; i++)
            {
                var row = lines[i].Replace('"', '\'');
                writer.WriteLine($"{name},\"{row}\"");
            }
        }
    }

    private static void IngestCsv(
        string path,
        string source,
        string kind,
        string[] preferLabelCols,
        int maxNodes,
        Action<string, string, string, (string, string)[]> addNode,
        Action<string, string, string, string?> addEdge,
        string crashNode,
        string edgeKind)
    {
        if (!File.Exists(path)) return;
        var lines = File.ReadAllLines(path);
        if (lines.Length < 2) return;
        var cols = SplitCsv(lines[0]);
        var labelIdx = preferLabelCols
            .Select(n => IndexOf(cols, n))
            .FirstOrDefault(i => i >= 0);
        if (labelIdx < 0) labelIdx = Math.Min(1, cols.Count - 1);

        var count = 0;
        for (var i = 1; i < lines.Length && count < maxNodes; i++)
        {
            var fields = SplitCsv(lines[i]);
            if (fields.Count == 0) continue;
            var label = labelIdx < fields.Count ? fields[labelIdx].Trim() : lines[i];
            if (string.IsNullOrWhiteSpace(label))
                label = $"{source}-row-{i}";
            if (label.Length > 120) label = label[..117] + "…";
            var id = $"{source}:{i}";
            addNode(id, kind, label, new[] { ("source", source) });
            addEdge(crashNode, id, edgeKind, source);
            count++;
        }
    }

    private static int IndexOf(IReadOnlyList<string> cols, string name)
    {
        for (var i = 0; i < cols.Count; i++)
        {
            if (cols[i].Trim().Trim('"').Equals(name, StringComparison.OrdinalIgnoreCase))
                return i;
        }

        return -1;
    }

    private static List<string> SplitCsv(string line)
    {
        var result = new List<string>();
        var sb = new StringBuilder();
        var inQuotes = false;
        for (var i = 0; i < line.Length; i++)
        {
            var ch = line[i];
            if (ch == '"')
            {
                if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                {
                    sb.Append('"');
                    i++;
                }
                else inQuotes = !inQuotes;
            }
            else if (ch == ',' && !inQuotes)
            {
                result.Add(sb.ToString());
                sb.Clear();
            }
            else sb.Append(ch);
        }

        result.Add(sb.ToString());
        return result;
    }
}
