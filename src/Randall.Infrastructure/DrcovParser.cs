using System.Globalization;
using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Parse DynamoRIO drcov text traces into basic-block edge keys.</summary>
public static partial class DrcovParser
{
    /// <summary>Module rows from a <c>-dump_text</c> drcov log (id → path, optional start/end).</summary>
    public static IReadOnlyList<DrcovModuleRow> ParseModules(string tracePath)
    {
        if (string.IsNullOrWhiteSpace(tracePath) || !File.Exists(tracePath))
            return [];

        var modules = new List<DrcovModuleRow>();
        var inModules = false;
        try
        {
            foreach (var line in File.ReadLines(tracePath))
            {
                if (line.StartsWith("Module Table:", StringComparison.OrdinalIgnoreCase))
                {
                    inModules = true;
                    continue;
                }

                if (line.StartsWith("BB Table:", StringComparison.OrdinalIgnoreCase))
                    break;

                if (!inModules || string.IsNullOrWhiteSpace(line))
                    continue;

                if (line.Contains("Columns:", StringComparison.OrdinalIgnoreCase))
                    continue;

                // Prefer "module[ id ]: … path"
                var bracket = ModuleLineBracket().Match(line);
                if (bracket.Success)
                {
                    modules.Add(new DrcovModuleRow(
                        bracket.Groups[1].Value.Trim(),
                        bracket.Groups[2].Value.Trim().Trim('"'),
                        null,
                        null));
                    continue;
                }

                // Classic CSV: id, containing_id, start, end, entry, …, path
                var trimmed = line.Trim();
                if (trimmed.Length == 0 || !char.IsDigit(trimmed[0]))
                    continue;
                var comma = trimmed.IndexOf(',');
                if (comma <= 0)
                    continue;
                var id = trimmed[..comma].Trim();
                var lastComma = trimmed.LastIndexOf(',');
                if (lastComma <= comma)
                    continue;
                var path = trimmed[(lastComma + 1)..].Trim().Trim('"');
                if (id.Length == 0 || path.Length == 0)
                    continue;
                // Skip header-ish rows without a path separator or binary suffix
                if (!path.Contains('\\') && !path.Contains('/') &&
                    !path.Contains(".exe", StringComparison.OrdinalIgnoreCase) &&
                    !path.Contains(".dll", StringComparison.OrdinalIgnoreCase) &&
                    !path.Contains(".so", StringComparison.OrdinalIgnoreCase))
                    continue;

                long? start = null, end = null;
                var fields = trimmed.Split(',');
                // version 2 columns: id, containing_id, start, end, entry, …
                if (fields.Length >= 4 &&
                    TryParseHexOrDec(fields[2].Trim(), out var s) &&
                    TryParseHexOrDec(fields[3].Trim(), out var e))
                {
                    start = s;
                    end = e;
                }

                modules.Add(new DrcovModuleRow(id, path, start, end));
            }
        }
        catch (IOException)
        {
            return [];
        }

        return modules;
    }

    /// <summary>
    /// Dynapstalker-style: keep BB edges whose module path contains <paramref name="processName"/>
    /// (case-insensitive). When <paramref name="processName"/> is null/empty, returns all edges.
    /// </summary>
    public static IReadOnlyList<string> ParseEdges(string tracePath, string? processName = null)
    {
        if (string.IsNullOrWhiteSpace(tracePath) || !File.Exists(tracePath))
            return [];

        HashSet<string>? allowIds = null;
        if (!string.IsNullOrWhiteSpace(processName))
        {
            var needle = processName.Trim();
            allowIds = ParseModules(tracePath)
                .Where(m =>
                    m.Path.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
                    Path.GetFileName(m.Path).Equals(needle, StringComparison.OrdinalIgnoreCase))
                .Select(m => m.Id)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            // If the name matched nothing, fall back to all edges rather than empty silence.
            if (allowIds.Count == 0)
                allowIds = null;
        }

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

                var moduleId = match.Groups[1].Value.Trim();
                if (allowIds is not null && !allowIds.Contains(moduleId))
                    continue;

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

    private static bool TryParseHexOrDec(string raw, out long value)
    {
        value = 0;
        var s = raw.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return long.TryParse(s[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
        return long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    [GeneratedRegex(@"^\s*(\d+)\s*,\s*(0x[0-9a-fA-F]+)\s*,\s*(\d+)")]
    private static partial Regex BbLineCsv();

    [GeneratedRegex(@"^\s*module\[\s*(\d+)\s*\]\s*:\s*(0x[0-9a-fA-F]+)\s*,\s*(\d+)")]
    private static partial Regex BbLineModuleBracket();

    [GeneratedRegex(@"^\s*module\[\s*(\d+)\s*\]\s*:.*\s(\S+\.(?:exe|dll|so|dylib))\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex ModuleLineBracket();
}

public sealed record DrcovModuleRow(string Id, string Path, long? Start = null, long? End = null);

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
