using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Parse DynamoRIO drcov text traces into basic-block edge keys.</summary>
public static partial class DrcovParser
{
    public static IReadOnlyList<string> ParseEdges(string tracePath)
    {
        if (string.IsNullOrWhiteSpace(tracePath) || !File.Exists(tracePath))
            return [];

        var edges = new List<string>();
        var inBbTable = false;
        try
        {
            foreach (var line in File.ReadLines(tracePath))
            {
                if (line.StartsWith("BB Table:", StringComparison.OrdinalIgnoreCase))
                {
                    inBbTable = true;
                    continue;
                }

                if (!inBbTable)
                    continue;

                if (string.IsNullOrWhiteSpace(line))
                    continue;

                // Header row: "module id, start, size:" (not a BB entry).
                if (line.Contains("module id", StringComparison.OrdinalIgnoreCase) &&
                    !line.Contains("module[", StringComparison.OrdinalIgnoreCase))
                    continue;

                // Windows/classic dump_text: "  9, 0x00001234, 16"
                // Linux dump_text (DRCOV v3): "module[  9]: 0x00001234,  16"
                var match = BbLineCsv().Match(line);
                if (!match.Success)
                    match = BbLineModuleBracket().Match(line);
                if (!match.Success)
                    continue;

                var moduleId = match.Groups[1].Value;
                var start = match.Groups[2].Value;
                var size = match.Groups[3].Value;
                edges.Add($"{moduleId}:{start}:{size}");
            }
        }
        catch (IOException)
        {
            return [];
        }

        return edges;
    }

    public static int CountEdges(string tracePath) => ParseEdges(tracePath).Count;

    [GeneratedRegex(@"^\s*(\d+)\s*,\s*(0x[0-9a-fA-F]+)\s*,\s*(\d+)")]
    private static partial Regex BbLineCsv();

    [GeneratedRegex(@"^\s*module\[\s*(\d+)\s*\]\s*:\s*(0x[0-9a-fA-F]+)\s*,\s*(\d+)")]
    private static partial Regex BbLineModuleBracket();
}

public sealed class CoverageSet(string? persistPath = null)
{
    private readonly HashSet<string> _edges = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long> _hitCounts = new(StringComparer.OrdinalIgnoreCase);
    private readonly string? _persistPath = persistPath;

    public void Load()
    {
        if (_persistPath is null || !File.Exists(_persistPath))
            return;
        foreach (var line in File.ReadLines(_persistPath))
        {
            if (!string.IsNullOrWhiteSpace(line))
            {
                var edge = line.Trim();
                _edges.Add(edge);
                _hitCounts.TryAdd(edge, 1);
            }
        }
    }

    public int RegisterTrace(string? tracePath)
    {
        if (string.IsNullOrWhiteSpace(tracePath))
            return 0;

        var newCount = 0;
        foreach (var edge in DrcovParser.ParseEdges(tracePath))
        {
            _hitCounts.TryGetValue(edge, out var hits);
            _hitCounts[edge] = hits + 1;

            if (_edges.Add(edge))
            {
                newCount++;
                if (_persistPath is not null)
                    File.AppendAllText(_persistPath, edge + Environment.NewLine);
            }
        }
        return newCount;
    }

    public int TotalEdges => _edges.Count;

    public long TotalHits => _hitCounts.Values.Sum();

    public IReadOnlyList<HotEdgeDto> GetTopHotEdges(int limit = 20) =>
        _hitCounts
            .OrderByDescending(kv => kv.Value)
            .Take(limit)
            .Select(kv => new HotEdgeDto(kv.Key, kv.Value))
            .ToList();
}
