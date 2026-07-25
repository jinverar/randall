using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// SaTC-style input-source → sink path scoring from Ghidra static map (call graph + xrefs).
/// Built into Oracle companion hints and static-map score bonuses — not a separate engine.
/// </summary>
public static class SourceSinkPathScorer
{
    public const int MaxHopDepth = 8;

    public static IReadOnlyList<RandallAnalysisSourceSinkPathDto> ScorePaths(RandallAnalysisDocument doc)
    {
        var sources = doc.Sinks
            .Where(s => s.Kind.Equals("input", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (sources.Count == 0)
        {
            sources = doc.Imports
                .Where(i => GhidraAnalysisBridge.IsInputSource(i.Name))
                .Select(i => new RandallAnalysisSinkDto(i.Name, i.Address, "input", 40, []))
                .ToList();
        }

        var sinks = doc.Sinks
            .Where(s => !s.Kind.Equals("input", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(s => s.Risk)
            .ToList();
        if (sinks.Count == 0)
            return [];

        var adjacency = BuildAdjacency(doc);
        var inputFunctions = ResolveInputFunctions(doc, sources);
        var sinkFunctions = ResolveSinkFunctions(doc, sinks);
        if (inputFunctions.Count == 0 || sinkFunctions.Count == 0)
            return [];

        var paths = new List<RandallAnalysisSourceSinkPathDto>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var src in sources.Take(12))
        {
            foreach (var sink in sinks.Take(16))
            {
                var key = $"{src.Name}->{sink.Name}";
                if (!seen.Add(key))
                    continue;

                var best = FindBestPath(inputFunctions, sinkFunctions, adjacency, src, sink);
                if (best is not null)
                    paths.Add(best);
            }
        }

        return paths
            .OrderByDescending(p => p.PathScore)
            .ThenBy(p => p.HopCount)
            .Take(24)
            .ToList();
    }

    public static int PathScoreBonus(string? functionName, RandallAnalysisDocument? doc)
    {
        if (doc is null || string.IsNullOrWhiteSpace(functionName))
            return 0;

        var paths = doc.SourceSinkPaths is { Count: > 0 }
            ? doc.SourceSinkPaths
            : ScorePaths(doc);

        var onPath = paths
            .Where(p => p.PathFunctions.Any(f =>
                f.Equals(functionName, StringComparison.OrdinalIgnoreCase)))
            .ToList();
        if (onPath.Count == 0)
            return 0;

        var top = onPath.Max(p => p.PathScore);
        return Math.Clamp(top / 10, 1, 15);
    }

    private static Dictionary<string, HashSet<string>> BuildAdjacency(RandallAnalysisDocument doc)
    {
        var adj = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);

        void AddEdge(string from, string to)
        {
            if (string.IsNullOrWhiteSpace(from) || string.IsNullOrWhiteSpace(to))
                return;
            if (!adj.TryGetValue(from, out var set))
            {
                set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                adj[from] = set;
            }
            set.Add(to);
        }

        foreach (var edge in doc.CallGraph ?? [])
            AddEdge(edge.Caller, edge.Callee);

        foreach (var xref in doc.Xrefs)
        {
            if (!xref.RefKind.Equals("call", StringComparison.OrdinalIgnoreCase))
                continue;
            AddEdge(xref.FromFunction, xref.ToSymbol);
        }

        foreach (var fn in doc.Functions)
        {
            foreach (var sink in fn.DangerousCalls)
            {
                var callee = doc.Functions.FirstOrDefault(f =>
                    f.Name.Equals(sink, StringComparison.OrdinalIgnoreCase));
                if (callee is not null)
                    AddEdge(fn.Name, callee.Name);
            }
        }

        return adj;
    }

    private static HashSet<string> ResolveInputFunctions(
        RandallAnalysisDocument doc,
        IReadOnlyList<RandallAnalysisSinkDto> sources)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var fn in doc.Functions.Where(f => f.InputReachable))
            set.Add(fn.Name);

        foreach (var src in sources)
        {
            foreach (var caller in src.Callers)
                set.Add(caller);

            foreach (var xref in doc.Xrefs)
            {
                if (!xref.ToSymbol.Equals(src.Name, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!string.IsNullOrWhiteSpace(xref.FromFunction))
                    set.Add(xref.FromFunction);
            }
        }

        return set;
    }

    private static HashSet<string> ResolveSinkFunctions(
        RandallAnalysisDocument doc,
        IReadOnlyList<RandallAnalysisSinkDto> sinks)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var sink in sinks)
        {
            foreach (var caller in sink.Callers)
                set.Add(caller);

            foreach (var fn in doc.Functions.Where(f =>
                         f.DangerousCalls.Any(c =>
                             c.Equals(sink.Name, StringComparison.OrdinalIgnoreCase))))
                set.Add(fn.Name);
        }

        return set;
    }

    private static RandallAnalysisSourceSinkPathDto? FindBestPath(
        HashSet<string> inputFunctions,
        HashSet<string> sinkFunctions,
        Dictionary<string, HashSet<string>> adjacency,
        RandallAnalysisSinkDto source,
        RandallAnalysisSinkDto sink)
    {
        RandallAnalysisSourceSinkPathDto? best = null;
        var bestScore = int.MinValue;

        foreach (var start in inputFunctions)
        {
            var path = BfsShortestPath(start, sinkFunctions, adjacency);
            if (path is null || path.Count < 2)
                continue;

            var hops = path.Count - 1;
            if (hops > MaxHopDepth)
                continue;

            var score = ComputePathScore(source, sink, hops, path);
            if (score <= bestScore)
                continue;

            bestScore = score;
            best = new RandallAnalysisSourceSinkPathDto(
                source.Name,
                sink.Name,
                score,
                hops,
                path,
                $"{source.Name} → {sink.Name} ({hops} hop(s), score {score})");
        }

        return best;
    }

    private static int ComputePathScore(
        RandallAnalysisSinkDto source,
        RandallAnalysisSinkDto sink,
        int hops,
        IReadOnlyList<string> path)
    {
        var sinkRisk = Math.Clamp(sink.Risk, 1, 100);
        var hopPenalty = Math.Clamp(hops * 6, 0, 48);
        var lengthBonus = path.Count >= 3 ? 8 : 0;
        return Math.Clamp(sinkRisk - hopPenalty + lengthBonus, 1, 100);
    }

    private static List<string>? BfsShortestPath(
        string start,
        HashSet<string> targets,
        Dictionary<string, HashSet<string>> adjacency)
    {
        if (targets.Contains(start))
            return [start];

        var queue = new Queue<string>();
        var prev = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        queue.Enqueue(start);
        prev[start] = null;

        while (queue.Count > 0)
        {
            var node = queue.Dequeue();
            if (!adjacency.TryGetValue(node, out var next))
                continue;

            foreach (var n in next)
            {
                if (prev.ContainsKey(n))
                    continue;
                prev[n] = node;
                if (targets.Contains(n))
                    return Reconstruct(prev, n);
                queue.Enqueue(n);
            }
        }

        return null;
    }

    private static List<string> Reconstruct(Dictionary<string, string?> prev, string end)
    {
        var path = new List<string>();
        string? cur = end;
        while (cur is not null)
        {
            path.Add(cur);
            cur = prev[cur];
        }
        path.Reverse();
        return path;
    }
}
