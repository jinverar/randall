using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Patch-analysis workflow v1 — compares two Ghidra analysis exports (or an existing
/// <see cref="GhidraAnalysisDiff"/> result) and surfaces security-relevant changed
/// function hints plus fuzz-target hints. Research/teaching only.
/// </summary>
public static class PatchAnalysisWorkflow
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    private static readonly HashSet<string> SecurityCallHints = new(StringComparer.OrdinalIgnoreCase)
    {
        "memcpy", "memmove", "strcpy", "strncpy", "strcat", "sprintf", "vsprintf",
        "snprintf", "scanf", "sscanf", "gets", "malloc", "realloc", "free",
        "system", "popen", "CreateProcess", "ShellExecute", "ReadFile", "recv",
        "recvfrom", "WSARecv",
    };

    /// <summary>
    /// Diff two analysis JSON paths via <see cref="GhidraAnalysisDiff"/> and build a summary.
    /// </summary>
    public static PatchAnalysisSummaryDto BuildFromPaths(string currentPath, string baselinePath)
    {
        try
        {
            if (!File.Exists(currentPath))
            {
                return Fail(currentPath, baselinePath, $"Current analysis not found: {currentPath}");
            }

            if (!File.Exists(baselinePath))
            {
                return Fail(currentPath, baselinePath, $"Baseline analysis not found: {baselinePath}");
            }

            var current = LoadAnalysis(currentPath);
            var baseline = LoadAnalysis(baselinePath);
            if (current is null || baseline is null)
                return Fail(currentPath, baselinePath, "Failed to deserialize one or both analysis documents.");

            var merged = GhidraAnalysisDiff.MergeDiff(current, baseline, baselinePath);
            return BuildFromDiff(merged, currentPath, baselinePath);
        }
        catch (Exception ex)
        {
            return Fail(currentPath, baselinePath, ex.Message);
        }
    }

    /// <summary>
    /// Build hints from an already-diffed <see cref="RandallAnalysisDocument"/>
    /// (populated <c>ChangedFunctions</c> from <see cref="GhidraAnalysisDiff"/>).
    /// </summary>
    public static PatchAnalysisSummaryDto BuildFromDiff(
        RandallAnalysisDocument diffed,
        string? currentPath = null,
        string? baselinePath = null)
    {
        var changed = (diffed.ChangedFunctions ?? []).ToList();

        var fnByName = diffed.Functions
            .GroupBy(f => f.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        var securityHints = new List<string>();
        var fuzzHints = new List<string>();

        foreach (var c in changed.OrderByDescending(x => x.ChangeScore).Take(24))
        {
            fnByName.TryGetValue(c.Name, out var fn);
            var securityRelevant = IsSecurityRelevant(c, fn, diffed);
            if (securityRelevant)
            {
                securityHints.Add(
                    $"{c.ChangeKind} {c.Name} @ {c.Address} (Δsize {c.SizeDelta:+0;-0}, " +
                    $"Δcomplexity {c.ComplexityDelta:+0;-0}, score {c.ChangeScore:0.##})" +
                    DescribeSecurityWhy(fn));
            }

            if (c.FuzzPriorityDelta != 0 || (fn?.FuzzPriority ?? 0) >= 60 || c.ChangeScore >= 0.35)
            {
                fuzzHints.Add(
                    $"Fuzz target hint: {c.Name} ({c.ChangeKind}) — priority Δ{c.FuzzPriorityDelta:+0;-0}" +
                    (fn is not null ? $", fuzz-priority {fn.FuzzPriority}/100" : "") +
                    (fn is { InputReachable: true } ? ", input-reachable" : ""));
            }
        }

        // Also surface high-priority unchanged sinks near changed callers when the map is rich.
        foreach (var sink in diffed.Sinks.OrderByDescending(s => s.Risk).Take(4))
        {
            if (changed.Any(c =>
                    c.Name.Equals(sink.Name, StringComparison.OrdinalIgnoreCase)
                    || sink.Callers.Any(caller =>
                        c.Name.Equals(caller, StringComparison.OrdinalIgnoreCase))))
            {
                var hint = $"Sink proximity: {sink.Name} (risk {sink.Risk}) near patched call graph";
                if (!securityHints.Contains(hint, StringComparer.OrdinalIgnoreCase))
                    securityHints.Add(hint);
            }
        }

        var top = changed
            .OrderByDescending(c => c.ChangeScore)
            .ThenByDescending(c => Math.Abs(c.FuzzPriorityDelta))
            .Take(8)
            .ToList();

        var summary = changed.Count == 0
            ? "No changed functions detected between analyses."
            : $"Patch analysis: {changed.Count} changed function(s); " +
              $"{securityHints.Count} security-relevant hint(s); {fuzzHints.Count} fuzz-target hint(s)." +
              (top.Count > 0 ? $" Top change: {top[0].Name} ({top[0].ChangeKind})." : "");

        return new PatchAnalysisSummaryDto(
            true,
            currentPath,
            baselinePath ?? diffed.DiffMeta?.BaselinePath,
            summary,
            securityHints,
            fuzzHints,
            top,
            DateTimeOffset.UtcNow);
    }

    public static string Write(string outputPath, PatchAnalysisSummaryDto summary)
    {
        var dir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);
        File.WriteAllText(outputPath, JsonSerializer.Serialize(summary, JsonOpts));
        return outputPath;
    }

    public static PatchAnalysisSummaryDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<PatchAnalysisSummaryDto>(File.ReadAllText(path), JsonOpts);
        }
        catch
        {
            return null;
        }
    }

    private static bool IsSecurityRelevant(
        RandallAnalysisChangedFunctionDto changed,
        RandallAnalysisFunctionDto? fn,
        RandallAnalysisDocument doc)
    {
        if (fn is { HasDangerousCalls: true })
            return true;
        if (fn is { InputReachable: true } && (changed.ChangeKind is "modified" or "added"))
            return true;
        if (Math.Abs(changed.SizeDelta) >= 32 || Math.Abs(changed.ComplexityDelta) >= 4)
            return true;
        if (fn?.DangerousCalls.Any(c => SecurityCallHints.Contains(c)) == true)
            return true;
        if (doc.Sinks.Any(s => s.Name.Equals(changed.Name, StringComparison.OrdinalIgnoreCase) && s.Risk >= 60))
            return true;
        if (changed.ChangeKind is "removed" && changed.ChangeScore >= 0.2)
            return true;
        return changed.ChangeScore >= 0.5;
    }

    private static string DescribeSecurityWhy(RandallAnalysisFunctionDto? fn)
    {
        if (fn is null)
            return "";
        var parts = new List<string>();
        if (fn.HasDangerousCalls && fn.DangerousCalls.Count > 0)
            parts.Add("dangerous calls: " + string.Join(", ", fn.DangerousCalls.Take(3)));
        if (fn.InputReachable)
            parts.Add("input-reachable");
        return parts.Count == 0 ? "" : " — " + string.Join("; ", parts);
    }

    private static RandallAnalysisDocument? LoadAnalysis(string path)
    {
        try
        {
            return GhidraAnalysisBridge.LoadOrThrow(path);
        }
        catch
        {
            try
            {
                return JsonSerializer.Deserialize<RandallAnalysisDocument>(File.ReadAllText(path), JsonOpts);
            }
            catch
            {
                return null;
            }
        }
    }

    private static PatchAnalysisSummaryDto Fail(string? current, string? baseline, string error) =>
        new(false, current, baseline, error, [], [], [], DateTimeOffset.UtcNow, error);
}
