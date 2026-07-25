using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Optional TraceRMI / GhidraMCP debugger correlation for crash RIP annotation.
/// Soft-fails when Ghidra MCP or debugger server is offline.
/// </summary>
public static class GhidraDebuggerCorrelation
{
    public static async Task<CrashRipAnnotationDto> AnnotateRipAsync(
        string ripAddress,
        string? project = null,
        string? repoRoot = null,
        CancellationToken ct = default)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var rip = NormalizeRip(ripAddress);

        StaticFunctionMappingDto? staticMap = null;
        if (!string.IsNullOrWhiteSpace(project))
        {
            var doc = GhidraAnalysisBridge.TryLoad(project, repoRoot);
            if (doc is not null && CrashStaticFunctionMapper.TryParseAddress(rip, out var pcVa))
            {
                var fn = GhidraAnalysisOracleHints.FindFunctionByAddress(doc, rip);
                if (fn is not null)
                {
                    staticMap = new StaticFunctionMappingDto(
                        "rip",
                        rip,
                        fn.Name,
                        "+0x0",
                        "ghidra",
                        null,
                        fn.DangerousCalls.Count > 0
                            ? "calls " + string.Join(", ", fn.DangerousCalls.Take(3))
                            : null,
                        fn.FuzzPriority > 0 ? fn.FuzzPriority : null);
                }
            }

            if (staticMap is null)
            {
                staticMap = CrashStaticFunctionMapper.TryMapFromCrash(
                    project,
                    null,
                    new CrashTriageDto("", "", "", false, false, "", null, null, null, rip, null),
                    repoRoot);
            }
        }

        var fnAddress = staticMap is not null
            ? ExtractFunctionBase(staticMap) ?? rip
            : rip;

        var decompiled = await GhidraMcpClient.TryDecompileFunctionAsync(fnAddress, ct);
        var debuggerStatic = await GhidraMcpClient.TryDebuggerDynamicToStaticAsync(rip, ct);

        var sources = new List<string>();
        if (staticMap is not null)
            sources.Add(staticMap.Source);
        if (decompiled is not null)
            sources.Add("ghidra-mcp-decompile");
        if (debuggerStatic is not null)
            sources.Add("ghidra-debugger");

        var source = sources.Count == 0 ? "none" : string.Join("+", sources);
        var summary = BuildSummary(rip, staticMap, decompiled, debuggerStatic);

        return new CrashRipAnnotationDto(
            rip,
            staticMap,
            TrimSnippet(decompiled),
            debuggerStatic,
            source,
            summary);
    }

    public static string FormatOneLine(CrashRipAnnotationDto ann)
    {
        var parts = new List<string> { $"RIP {ann.RipAddress}" };
        if (ann.StaticMap is not null)
            parts.Add(CrashStaticFunctionMapper.FormatOneLine(ann.StaticMap));
        if (ann.DebuggerStaticAddress is not null)
            parts.Add($"debugger→static {ann.DebuggerStaticAddress}");
        return string.Join(" · ", parts);
    }

    private static string BuildSummary(
        string rip,
        StaticFunctionMappingDto? staticMap,
        string? decompiled,
        string? debuggerStatic)
    {
        if (staticMap is null && decompiled is null && debuggerStatic is null)
            return $"No Ghidra context for RIP {rip} (offline or no static map).";

        var parts = new List<string>();
        if (staticMap is not null)
            parts.Add($"{staticMap.FunctionName}{staticMap.Offset} ({staticMap.Source})");
        if (debuggerStatic is not null)
            parts.Add($"TraceRMI static {debuggerStatic}");
        if (decompiled is not null)
            parts.Add("decompiled snippet available");
        return string.Join("; ", parts);
    }

    private static string? ExtractFunctionBase(StaticFunctionMappingDto map)
    {
        if (string.IsNullOrWhiteSpace(map.PcAddress))
            return null;
        if (!CrashStaticFunctionMapper.TryParseAddress(map.PcAddress, out var pc))
            return map.PcAddress;
        if (map.Offset.StartsWith("+0x", StringComparison.OrdinalIgnoreCase) &&
            ulong.TryParse(map.Offset[3..], System.Globalization.NumberStyles.HexNumber, null, out var off))
        {
            var baseVa = pc >= off ? pc - off : pc;
            return $"0x{baseVa:x}";
        }
        return map.PcAddress;
    }

    private static string NormalizeRip(string rip)
    {
        var s = rip.Trim();
        return s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? s.ToLowerInvariant() : "0x" + s;
    }

    private static string? TrimSnippet(string? decompiled)
    {
        if (string.IsNullOrWhiteSpace(decompiled))
            return null;
        var lines = decompiled
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Take(12);
        var text = string.Join(Environment.NewLine, lines);
        return text.Length <= 800 ? text : text[..800] + "…";
    }
}
