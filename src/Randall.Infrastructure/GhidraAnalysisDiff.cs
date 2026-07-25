using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Compare two Ghidra static maps without BinDiff — name/address keyed heuristics for patch-hunt hints.
/// Optional BinExport/BinDiff companions are documented; this path works from JSON alone.
/// </summary>
public static class GhidraAnalysisDiff
{
    public const string JsonMergeSource = "json-merge";

    public static RandallAnalysisDocument MergeDiff(
        RandallAnalysisDocument current,
        RandallAnalysisDocument baseline,
        string baselinePath,
        string source = JsonMergeSource)
    {
        var changed = ComputeChangedFunctions(current, baseline);
        var meta = new RandallAnalysisDiffMetaDto(
            baselinePath,
            baseline.Binary,
            baseline.BinarySha256,
            DateTime.UtcNow.ToString("o"),
            source);

        return current with
        {
            ChangedFunctions = changed,
            DiffMeta = meta,
        };
    }

    public static RandallAnalysisDocument WithBsimMatches(
        RandallAnalysisDocument doc,
        IReadOnlyList<RandallAnalysisBsimMatchDto> matches) =>
        doc with { BsimMatches = matches.Count > 0 ? matches : null };

    public static IReadOnlyList<RandallAnalysisChangedFunctionDto> ComputeChangedFunctions(
        RandallAnalysisDocument current,
        RandallAnalysisDocument baseline)
    {
        var baselineByName = BuildNameIndex(baseline.Functions);
        var baselineByOffset = BuildOffsetIndex(baseline.Functions, baseline.ImageBase);
        var matchedBaseline = new HashSet<RandallAnalysisFunctionDto>(ReferenceEqualityComparer.Instance);

        var results = new List<RandallAnalysisChangedFunctionDto>();

        foreach (var fn in current.Functions)
        {
            var match = FindBaselineMatch(fn, baselineByName, baselineByOffset, current.ImageBase);
            if (match is null)
            {
                results.Add(new RandallAnalysisChangedFunctionDto(
                    fn.Name,
                    fn.Address,
                    "added",
                    null,
                    null,
                    fn.Size,
                    fn.Complexity,
                    fn.BasicBlockCount,
                    fn.FuzzPriority,
                    ComputeChangeScore(fn.Size, fn.Complexity, fn.BasicBlockCount, 0, 0, 0)));
                continue;
            }

            matchedBaseline.Add(match);
            var sizeDelta = fn.Size - match.Size;
            var complexityDelta = fn.Complexity - match.Complexity;
            var bbDelta = fn.BasicBlockCount - match.BasicBlockCount;
            var priorityDelta = fn.FuzzPriority - match.FuzzPriority;

            if (!IsModified(sizeDelta, complexityDelta, bbDelta, fn.Name, match.Name))
                continue;

            var kind = fn.Name.Equals(match.Name, StringComparison.OrdinalIgnoreCase)
                ? "modified"
                : "renamed";

            results.Add(new RandallAnalysisChangedFunctionDto(
                fn.Name,
                fn.Address,
                kind,
                match.Name,
                match.Address,
                sizeDelta,
                complexityDelta,
                bbDelta,
                priorityDelta,
                ComputeChangeScore(fn.Size, fn.Complexity, fn.BasicBlockCount,
                    match.Size, match.Complexity, match.BasicBlockCount)));
        }

        foreach (var fn in baseline.Functions)
        {
            if (matchedBaseline.Contains(fn))
                continue;

            results.Add(new RandallAnalysisChangedFunctionDto(
                fn.Name,
                fn.Address,
                "removed",
                fn.Name,
                fn.Address,
                -fn.Size,
                -fn.Complexity,
                -fn.BasicBlockCount,
                -fn.FuzzPriority,
                ComputeChangeScore(0, 0, 0, fn.Size, fn.Complexity, fn.BasicBlockCount)));
        }

        return results
            .OrderByDescending(c => c.ChangeScore)
            .ThenByDescending(c => Math.Abs(c.SizeDelta))
            .ToList();
    }

    public static IReadOnlyList<RandallAnalysisBsimMatchDto> ParseBsimJson(string jsonPath)
    {
        var json = File.ReadAllText(jsonPath);
        var rows = System.Text.Json.JsonSerializer.Deserialize<List<BsimJsonRow>>(
            json,
            new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? [];

        return rows
            .Where(r => !string.IsNullOrWhiteSpace(r.QueryFunction) || !string.IsNullOrWhiteSpace(r.QueryAddress))
            .Select(r => new RandallAnalysisBsimMatchDto(
                r.QueryFunction ?? "",
                r.QueryAddress ?? "",
                r.MatchFunction ?? "",
                r.MatchAddress ?? "",
                r.Similarity,
                r.MatchBinary,
                string.IsNullOrWhiteSpace(r.Source) ? "bsim" : r.Source!))
            .OrderByDescending(m => m.Similarity)
            .ToList();
    }

    private sealed class BsimJsonRow
    {
        public string? QueryFunction { get; set; }
        public string? QueryAddress { get; set; }
        public string? MatchFunction { get; set; }
        public string? MatchAddress { get; set; }
        public double Similarity { get; set; }
        public string? MatchBinary { get; set; }
        public string? Source { get; set; }
    }

    private static Dictionary<string, RandallAnalysisFunctionDto> BuildNameIndex(
        IReadOnlyList<RandallAnalysisFunctionDto> functions)
    {
        var map = new Dictionary<string, RandallAnalysisFunctionDto>(StringComparer.OrdinalIgnoreCase);
        foreach (var fn in functions)
        {
            if (!map.ContainsKey(fn.Name))
                map[fn.Name] = fn;
        }

        return map;
    }

    private static Dictionary<ulong, RandallAnalysisFunctionDto> BuildOffsetIndex(
        IReadOnlyList<RandallAnalysisFunctionDto> functions,
        string imageBase)
    {
        var map = new Dictionary<ulong, RandallAnalysisFunctionDto>();
        foreach (var fn in functions)
        {
            if (!TryFunctionOffset(fn.Address, imageBase, out var offset))
                continue;
            if (!map.ContainsKey(offset))
                map[offset] = fn;
        }

        return map;
    }

    private static RandallAnalysisFunctionDto? FindBaselineMatch(
        RandallAnalysisFunctionDto fn,
        Dictionary<string, RandallAnalysisFunctionDto> byName,
        Dictionary<ulong, RandallAnalysisFunctionDto> byOffset,
        string currentImageBase)
    {
        if (byName.TryGetValue(fn.Name, out var byNameMatch))
            return byNameMatch;

        if (TryFunctionOffset(fn.Address, currentImageBase, out var offset) &&
            byOffset.TryGetValue(offset, out var byOffsetMatch))
            return byOffsetMatch;

        return null;
    }

    private static bool IsModified(
        int sizeDelta,
        int complexityDelta,
        int bbDelta,
        string currentName,
        string baselineName)
    {
        if (!currentName.Equals(baselineName, StringComparison.OrdinalIgnoreCase))
            return true;
        if (Math.Abs(sizeDelta) >= 4)
            return true;
        if (Math.Abs(complexityDelta) >= 3)
            return true;
        if (Math.Abs(bbDelta) >= 2)
            return true;
        return false;
    }

    private static double ComputeChangeScore(
        int size, int complexity, int bb,
        int baseSize, int baseComplexity, int baseBb)
    {
        var sizeDelta = Math.Abs(size - baseSize);
        var complexityDelta = Math.Abs(complexity - baseComplexity);
        var bbDelta = Math.Abs(bb - baseBb);

        var score = 0.0;
        score += Math.Min(40, sizeDelta / 4.0);
        score += Math.Min(35, complexityDelta * 1.5);
        score += Math.Min(25, bbDelta * 3.0);
        return Math.Round(Math.Clamp(score, 0, 100), 1);
    }

    private static bool TryFunctionOffset(string address, string imageBase, out ulong offset)
    {
        offset = 0;
        if (!TryParseAddr(address, out var addr))
            return false;
        if (!TryParseAddr(imageBase, out var ib))
            ib = 0;

        offset = addr >= ib ? addr - ib : addr;
        return true;
    }

    private static bool TryParseAddr(string addr, out ulong value)
    {
        value = 0;
        var s = addr.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            s = s[2..];
        return ulong.TryParse(s, System.Globalization.NumberStyles.HexNumber,
            System.Globalization.CultureInfo.InvariantCulture, out value);
    }
}
