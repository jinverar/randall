using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Call-graph utilities for Ghidra static map: merge edges, input→sink paths, frontier proximity.
/// </summary>
public static class GhidraCallGraphHelper
{
    public static RandallAnalysisDocument EnrichCallGraph(RandallAnalysisDocument doc)
    {
        var merged = MergeCallGraph(doc);
        if (merged.Count <= (doc.CallGraph?.Count ?? 0))
            return doc;
        return doc with { CallGraph = merged };
    }

    /// <summary>
    /// Union script export, xref-derived edges, and function callee lists into one deduped graph.
    /// </summary>
    public static IReadOnlyList<RandallAnalysisCallEdgeDto> MergeCallGraph(RandallAnalysisDocument doc)
    {
        var edges = new Dictionary<string, RandallAnalysisCallEdgeDto>(StringComparer.OrdinalIgnoreCase);

        void Add(string caller, string callee, string callSite)
        {
            if (string.IsNullOrWhiteSpace(caller) || string.IsNullOrWhiteSpace(callee))
                return;
            var key = $"{caller}|{callee}|{callSite}";
            edges[key] = new RandallAnalysisCallEdgeDto(caller, callee, callSite);
        }

        if (doc.CallGraph is not null)
        {
            foreach (var e in doc.CallGraph)
                Add(e.Caller, e.Callee, e.CallSite);
        }

        foreach (var x in doc.Xrefs)
        {
            if (!x.RefKind.Equals("call", StringComparison.OrdinalIgnoreCase))
                continue;
            Add(x.FromFunction, x.ToSymbol, x.FromAddress);
        }

        foreach (var fn in doc.Functions)
        {
            foreach (var imp in doc.Imports)
            {
                if (!fn.DangerousCalls.Contains(imp.Name, StringComparer.OrdinalIgnoreCase) &&
                    !GhidraAnalysisBridge.IsInputSource(imp.Name))
                    continue;
                if (doc.Sinks.Any(s => s.Callers.Contains(fn.Name, StringComparer.OrdinalIgnoreCase) &&
                                       s.Name.Equals(imp.Name, StringComparison.OrdinalIgnoreCase)))
                    Add(fn.Name, imp.Name, fn.Address);
            }
        }

        return edges.Values
            .OrderBy(e => e.Caller, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.Callee, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.CallSite, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// BFS on call graph from any function/symbol matching <paramref name="fromNeedle"/> to one matching <paramref name="toNeedle"/>.
    /// </summary>
    public static IReadOnlyList<string>? TryFindCallPath(
        RandallAnalysisDocument doc,
        string fromNeedle,
        string toNeedle)
    {
        if (string.IsNullOrWhiteSpace(fromNeedle) || string.IsNullOrWhiteSpace(toNeedle))
            return null;

        var graph = MergeCallGraph(doc);
        if (graph.Count == 0 && doc.Xrefs.Count == 0)
            return null;

        var adj = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in graph)
        {
            if (!adj.TryGetValue(e.Caller, out var list))
            {
                list = [];
                adj[e.Caller] = list;
            }
            if (!list.Contains(e.Callee, StringComparer.OrdinalIgnoreCase))
                list.Add(e.Callee);
        }

        var starts = ResolveStartNodes(doc, fromNeedle, adj);
        var targets = ResolveTargetNodes(doc, toNeedle, adj);
        if (starts.Count == 0 || targets.Count == 0)
            return null;

        foreach (var start in starts)
        {
            var path = BfsPath(start, targets, adj, toNeedle);
            if (path is not null)
                return path;
        }

        return null;
    }

    private static HashSet<string> ResolveStartNodes(
        RandallAnalysisDocument doc,
        string fromNeedle,
        Dictionary<string, List<string>> adj)
    {
        var starts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var sink in doc.Sinks.Where(s => MatchesNeedle(s.Name, fromNeedle)))
        {
            foreach (var caller in sink.Callers)
                starts.Add(caller);
        }

        foreach (var xref in doc.Xrefs)
        {
            if (!xref.RefKind.Equals("call", StringComparison.OrdinalIgnoreCase))
                continue;
            if (!MatchesNeedle(xref.ToSymbol, fromNeedle))
                continue;
            if (!string.IsNullOrWhiteSpace(xref.FromFunction))
                starts.Add(xref.FromFunction);
        }

        foreach (var fn in doc.Functions.Where(f => f.InputReachable))
            starts.Add(fn.Name);

        foreach (var key in adj.Keys.Where(k => MatchesNeedle(k, fromNeedle)))
            starts.Add(key);

        if (starts.Count == 0)
            starts.Add(fromNeedle);
        return starts;
    }

    private static HashSet<string> ResolveTargetNodes(
        RandallAnalysisDocument doc,
        string toNeedle,
        Dictionary<string, List<string>> adj)
    {
        var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var sink in doc.Sinks.Where(s => MatchesNeedle(s.Name, toNeedle)))
            targets.Add(sink.Name);

        foreach (var fn in doc.Functions.Where(f =>
                     f.DangerousCalls.Any(c => MatchesNeedle(c, toNeedle))))
            targets.Add(fn.Name);

        foreach (var key in adj.Keys.Where(k => MatchesNeedle(k, toNeedle)))
            targets.Add(key);

        targets.Add(toNeedle);
        return targets;
    }

    public static FrontierBranchDto? FindNearestFrontier(
        string? functionName,
        FrontierReportDto? frontier)
    {
        if (frontier?.Frontiers is not { Count: > 0 } list)
            return null;

        if (!string.IsNullOrWhiteSpace(functionName))
        {
            var inFn = list
                .Where(f => !string.IsNullOrWhiteSpace(f.FunctionName) &&
                            f.FunctionName.Equals(functionName, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(f => f.Score)
                .FirstOrDefault();
            if (inFn is not null)
                return inFn;
        }

        return list.OrderByDescending(f => f.Score).FirstOrDefault();
    }

    public static string FormatCallPath(IReadOnlyList<string> path) =>
        string.Join(" → ", path);

    private static IReadOnlyList<string>? BfsPath(
        string start,
        HashSet<string> targets,
        Dictionary<string, List<string>> adj,
        string sinkNeedle)
    {
        if (targets.Contains(start) || MatchesNeedle(start, sinkNeedle))
            return [start];

        var queue = new Queue<string>();
        var prev = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        queue.Enqueue(start);
        prev[start] = null;

        while (queue.Count > 0)
        {
            var node = queue.Dequeue();
            if (!adj.TryGetValue(node, out var next))
                continue;

            foreach (var n in next)
            {
                if (prev.ContainsKey(n))
                    continue;
                prev[n] = node;
                if (targets.Contains(n) || MatchesNeedle(n, sinkNeedle))
                    return Reconstruct(prev, n);
                queue.Enqueue(n);
            }
        }

        return null;
    }

    private static IReadOnlyList<string> Reconstruct(Dictionary<string, string?> prev, string end)
    {
        var path = new List<string>();
        for (var cur = end; cur is not null; cur = prev[cur])
            path.Add(cur);
        path.Reverse();
        return path;
    }

    private static bool MatchesNeedle(string symbol, string needle) =>
        symbol.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
        needle.Contains(symbol, StringComparison.OrdinalIgnoreCase);
}
