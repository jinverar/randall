using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Randall.Infrastructure;

/// <summary>
/// Thin HTTP adapter for a running GhidraMCP plugin (bethington/ghidra-mcp).
/// Soft-fails when the server is offline — never required for fuzz/CI.
/// </summary>
public static class GhidraMcpClient
{
    public const int DefaultPort = 8089;

    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(8) };

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public sealed record ProbeResult(bool Available, string Message, string? ProgramName, string BaseUrl);

    public sealed record ImportEntry(string Name, string? Library, string Address);

    public sealed record XrefEntry(string FromAddress, string? FromFunction, string RefKind);

    public sealed record ImportCallersResult(
        string ImportName,
        string ImportAddress,
        IReadOnlyList<XrefEntry> Callers,
        string Source);

    public sealed record InputToSinkPathResult(
        string InputImport,
        string SinkImport,
        IReadOnlyList<string> Path,
        string Source,
        string Summary);

    public sealed record DecompileResult(string Address, string? Code, string Source);

    public sealed record DebuggerTranslateResult(string DynamicAddress, string? StaticAddress, string Source);

    public static string ResolveBaseUrl()
    {
        var explicitUrl = Environment.GetEnvironmentVariable("GHIDRA_MCP_URL");
        if (!string.IsNullOrWhiteSpace(explicitUrl))
            return explicitUrl.TrimEnd('/');

        var port = DefaultPort;
        var portText = Environment.GetEnvironmentVariable("GHIDRA_MCP_PORT");
        if (!string.IsNullOrWhiteSpace(portText) && int.TryParse(portText, out var parsed) && parsed is > 0 and < 65536)
            port = parsed;

        return $"http://127.0.0.1:{port}";
    }

    public static async Task<ProbeResult> ProbeAsync(CancellationToken ct = default)
    {
        var baseUrl = ResolveBaseUrl();
        foreach (var path in new[] { "/check_connection", "/mcp/health", "/health" })
        {
            try
            {
                var body = await GetTextAsync($"{baseUrl}{path}", ct);
                if (string.IsNullOrWhiteSpace(body))
                    continue;

                var program = ExtractProgramName(body);
                return new ProbeResult(true, body.Trim(), program, baseUrl);
            }
            catch (HttpRequestException)
            {
                // try next path
            }
            catch (TaskCanceledException)
            {
                return new ProbeResult(false, "Ghidra MCP request timed out.", null, baseUrl);
            }
        }

        return new ProbeResult(
            false,
            "Ghidra MCP HTTP server not reachable (start Tools → GhidraMCP → Start MCP Server in Ghidra).",
            null,
            baseUrl);
    }

    public static async Task<IReadOnlyList<ImportEntry>?> TryListImportsAsync(
        string? nameFilter = null,
        CancellationToken ct = default)
    {
        if (await ProbeAsync(ct) is not { Available: true })
            return null;

        var raw = await GetTextAsync($"{ResolveBaseUrl()}/list_imports", ct);
        var imports = ParseImports(raw);
        if (string.IsNullOrWhiteSpace(nameFilter))
            return imports;

        return imports
            .Where(i => i.Name.Contains(nameFilter, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    public static async Task<ImportCallersResult?> TryGetImportCallersAsync(
        string importName,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(importName))
            throw new ArgumentException("import name required", nameof(importName));

        if (await ProbeAsync(ct) is not { Available: true })
            return null;

        var imports = await TryListImportsAsync(null, ct);
        if (imports is null || imports.Count == 0)
            return null;

        var match = imports.FirstOrDefault(i =>
                       i.Name.Equals(importName, StringComparison.OrdinalIgnoreCase))
                    ?? imports.FirstOrDefault(i =>
                       i.Name.Contains(importName, StringComparison.OrdinalIgnoreCase));
        if (match is null)
            return new ImportCallersResult(importName, "", [], "import-not-found");

        var xrefs = await TryGetXrefsToAsync(match.Address, ct) ?? [];
        return new ImportCallersResult(match.Name, match.Address, xrefs, "ghidra-mcp-live");
    }

    /// <summary>
    /// Trace a static call path from an input import (e.g. recv) toward a sink (e.g. memcpy).
    /// Uses <c>randall-analysis.json</c> when present; optionally validates leaf via live MCP.
    /// </summary>
    public static async Task<InputToSinkPathResult?> TryTraceInputToSinkPathAsync(
        string project,
        string inputImport,
        string sinkImport,
        string? repoRoot = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(inputImport) || string.IsNullOrWhiteSpace(sinkImport))
            throw new ArgumentException("input and sink import names required");

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var doc = GhidraAnalysisBridge.TryLoad(project, repoRoot);
        IReadOnlyList<string>? path = null;
        var source = "static-map";

        if (doc is not null)
        {
            path = GhidraCallGraphHelper.TryFindCallPath(doc, inputImport, sinkImport);
            if (path is not null && path.Count > 0)
                source = "randall-analysis.json";
        }

        if (path is null || path.Count == 0)
        {
            if (await ProbeAsync(ct) is not { Available: true })
                return null;

            path = await TryBuildLiveCallChainAsync(inputImport, sinkImport, ct);
            if (path is null || path.Count == 0)
                return null;
            source = "ghidra-mcp-live";
        }
        else if (await ProbeAsync(ct) is { Available: true })
        {
            var leaf = path[^1];
            if (!leaf.Contains(sinkImport, StringComparison.OrdinalIgnoreCase))
            {
                var liveTail = await TryBuildLiveCallChainAsync(path[^1], sinkImport, ct);
                if (liveTail is { Count: > 1 })
                {
                    path = path.Concat(liveTail.Skip(1)).ToList();
                    source = "static-map+mcp";
                }
            }
        }

        var summary = GhidraCallGraphHelper.FormatCallPath(path);
        return new InputToSinkPathResult(inputImport, sinkImport, path, source, summary);
    }

    private static async Task<IReadOnlyList<string>?> TryBuildLiveCallChainAsync(
        string fromImport,
        string toImport,
        CancellationToken ct,
        int maxDepth = 8)
    {
        var callers = await TryGetImportCallersAsync(fromImport, ct);
        if (callers is null || callers.Callers.Count == 0)
            return [fromImport];

        var queue = new Queue<(string Symbol, List<string> Path)>();
        queue.Enqueue((fromImport, [fromImport]));

        while (queue.Count > 0)
        {
            var (symbol, path) = queue.Dequeue();
            if (path.Count > maxDepth)
                continue;

            if (symbol.Contains(toImport, StringComparison.OrdinalIgnoreCase) ||
                toImport.Contains(symbol, StringComparison.OrdinalIgnoreCase))
                return path;

            var next = symbol.Equals(fromImport, StringComparison.OrdinalIgnoreCase)
                ? callers
                : null;
            if (next is null && !string.IsNullOrWhiteSpace(symbol))
            {
                var fnCallers = await TryGetFunctionCallersAsync(symbol, ct);
                if (fnCallers is { Count: > 0 })
                {
                    foreach (var c in fnCallers.Take(6))
                    {
                        var fn = c.FromFunction ?? c.FromAddress;
                        if (string.IsNullOrWhiteSpace(fn))
                            continue;
                        queue.Enqueue((fn, path.Concat([fn]).ToList()));
                    }
                    continue;
                }
            }

            foreach (var c in (next?.Callers ?? []).Take(8))
            {
                var fn = c.FromFunction ?? c.FromAddress;
                if (string.IsNullOrWhiteSpace(fn))
                    continue;
                queue.Enqueue((fn, path.Concat([fn]).ToList()));
            }
        }

        return null;
    }

    private static async Task<IReadOnlyList<XrefEntry>?> TryGetFunctionCallersAsync(
        string functionName,
        CancellationToken ct)
    {
        if (await ProbeAsync(ct) is not { Available: true })
            return null;

        try
        {
            var raw = await GetTextAsync(
                $"{ResolveBaseUrl()}/get_callers?function={Uri.EscapeDataString(functionName)}", ct);
            return await ParseXrefsAsync(raw, ct);
        }
        catch (HttpRequestException)
        {
            return null;
        }
    }

    public static async Task<IReadOnlyList<XrefEntry>?> TryGetXrefsToAsync(
        string address,
        CancellationToken ct = default)
    {
        if (await ProbeAsync(ct) is not { Available: true })
            return null;

        var addr = NormalizeAddress(address);
        var raw = await GetTextAsync($"{ResolveBaseUrl()}/get_xrefs_to?address={Uri.EscapeDataString(addr)}", ct);
        return await ParseXrefsAsync(raw, ct);
    }

    /// <summary>Decompile function at address via GhidraMCP (soft-fail offline).</summary>
    public static async Task<string?> TryDecompileFunctionAsync(
        string address,
        CancellationToken ct = default)
    {
        if (await ProbeAsync(ct) is not { Available: true })
            return null;

        var addr = NormalizeAddress(address);
        foreach (var path in new[]
                 {
                     $"/decompile_function?address={Uri.EscapeDataString(addr)}",
                     $"/decompile?address={Uri.EscapeDataString(addr)}",
                 })
        {
            try
            {
                var raw = await GetTextAsync($"{ResolveBaseUrl()}{path}", ct);
                if (string.IsNullOrWhiteSpace(raw) ||
                    raw.StartsWith("Error", StringComparison.OrdinalIgnoreCase))
                    continue;
                return raw.Trim();
            }
            catch (HttpRequestException)
            {
                // try next endpoint variant
            }
        }

        return null;
    }

    /// <summary>
    /// Translate runtime dynamic address to static Ghidra address via TraceRMI debugger proxy.
    /// Requires Ghidra debugger server (default http://127.0.0.1:8099/) — soft-fails offline.
    /// </summary>
    public static async Task<string?> TryDebuggerDynamicToStaticAsync(
        string dynamicAddress,
        CancellationToken ct = default)
    {
        var addr = NormalizeAddress(dynamicAddress);
        var debuggerBase = ResolveDebuggerBaseUrl();

        foreach (var baseUrl in new[] { debuggerBase, ResolveBaseUrl() })
        {
            foreach (var path in new[]
                     {
                         $"/debugger_dynamic_to_static?address={Uri.EscapeDataString(addr)}",
                         $"/debugger/dynamic_to_static?address={Uri.EscapeDataString(addr)}",
                     })
            {
                try
                {
                    var raw = await GetTextAsync($"{baseUrl}{path}", ct);
                    var translated = ParseDebuggerAddress(raw);
                    if (translated is not null)
                        return translated;
                }
                catch (HttpRequestException)
                {
                    // soft-fail
                }
                catch (TaskCanceledException)
                {
                    return null;
                }
            }
        }

        return null;
    }

    public static string ResolveDebuggerBaseUrl()
    {
        var explicitUrl = Environment.GetEnvironmentVariable("GHIDRA_DEBUGGER_URL");
        if (!string.IsNullOrWhiteSpace(explicitUrl))
            return explicitUrl.TrimEnd('/');

        var portText = Environment.GetEnvironmentVariable("GHIDRA_DEBUGGER_PORT");
        if (!string.IsNullOrWhiteSpace(portText) &&
            int.TryParse(portText, out var parsed) &&
            parsed is > 0 and < 65536)
            return $"http://127.0.0.1:{parsed}";

        return "http://127.0.0.1:8099";
    }

    internal static string? ParseDebuggerAddress(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        if (raw.TrimStart().StartsWith('{'))
        {
            try
            {
                using var doc = JsonDocument.Parse(raw);
                foreach (var name in new[] { "staticAddress", "static_address", "address", "result" })
                {
                    if (doc.RootElement.TryGetProperty(name, out var el) &&
                        el.ValueKind == JsonValueKind.String)
                    {
                        var s = el.GetString();
                        if (!string.IsNullOrWhiteSpace(s))
                            return NormalizeAddress(s);
                    }
                }
            }
            catch (JsonException)
            {
                // fall through
            }
        }

        var extracted = ExtractAddress(raw);
        return extracted;
    }

    internal static IReadOnlyList<ImportEntry> ParseImports(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return [];

        if (raw.TrimStart().StartsWith('{') || raw.TrimStart().StartsWith('['))
        {
            try
            {
                using var doc = JsonDocument.Parse(raw);
                return ParseImportsFromJson(doc.RootElement);
            }
            catch (JsonException)
            {
                // fall through to text parsing
            }
        }

        var list = new List<ImportEntry>();
        foreach (var line in raw.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var entry = ParseImportLine(line);
            if (entry is not null)
                list.Add(entry);
        }

        return list;
    }

    internal static async Task<IReadOnlyList<XrefEntry>> ParseXrefsAsync(string raw, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return [];

        if (raw.TrimStart().StartsWith('{') || raw.TrimStart().StartsWith('['))
        {
            try
            {
                using var doc = JsonDocument.Parse(raw);
                return await ParseXrefsFromJsonAsync(doc.RootElement, ct);
            }
            catch (JsonException)
            {
                // fall through
            }
        }

        var list = new List<XrefEntry>();
        foreach (var line in raw.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var addr = ExtractAddress(line);
            if (addr is null)
                continue;
            var fn = await TryResolveFunctionNameAsync(addr, ct);
            list.Add(new XrefEntry(addr, fn, GuessRefKind(line)));
        }

        return list;
    }

    private static async Task<string?> TryResolveFunctionNameAsync(string address, CancellationToken ct)
    {
        try
        {
            var addr = NormalizeAddress(address);
            var raw = await GetTextAsync(
                $"{ResolveBaseUrl()}/get_function_by_address?address={Uri.EscapeDataString(addr)}", ct);
            if (string.IsNullOrWhiteSpace(raw))
                return null;

            if (raw.TrimStart().StartsWith('{'))
            {
                using var doc = JsonDocument.Parse(raw);
                if (doc.RootElement.TryGetProperty("name", out var nameEl))
                    return nameEl.GetString();
                if (doc.RootElement.TryGetProperty("function", out var fnEl) &&
                    fnEl.TryGetProperty("name", out var nested))
                    return nested.GetString();
            }

            var m = Regex.Match(raw, @"\bname\s*[:=]\s*['""]?([^'""\r\n]+)", RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value.Trim() : null;
        }
        catch
        {
            return null;
        }
    }

    private static IReadOnlyList<ImportEntry> ParseImportsFromJson(JsonElement root)
    {
        var list = new List<ImportEntry>();
        var items = root.ValueKind == JsonValueKind.Array
            ? root.EnumerateArray()
            : root.TryGetProperty("imports", out var imp) && imp.ValueKind == JsonValueKind.Array
                ? imp.EnumerateArray()
                : root.EnumerateObject().SelectMany(p => p.Value.ValueKind == JsonValueKind.Array
                    ? p.Value.EnumerateArray()
                    : []);

        foreach (var item in items)
        {
            if (item.ValueKind != JsonValueKind.Object)
                continue;
            var name = GetString(item, "name", "symbol", "import");
            var addr = GetString(item, "address", "addr", "location");
            var lib = GetString(item, "library", "dll", "module");
            if (name is not null && addr is not null)
                list.Add(new ImportEntry(name, lib, NormalizeAddress(addr)));
        }

        return list;
    }

    private static async Task<IReadOnlyList<XrefEntry>> ParseXrefsFromJsonAsync(JsonElement root, CancellationToken ct)
    {
        var list = new List<XrefEntry>();
        var items = root.ValueKind == JsonValueKind.Array
            ? root.EnumerateArray()
            : root.TryGetProperty("xrefs", out var xr) && xr.ValueKind == JsonValueKind.Array
                ? xr.EnumerateArray()
                : root.EnumerateObject().SelectMany(p => p.Value.ValueKind == JsonValueKind.Array
                    ? p.Value.EnumerateArray()
                    : []);

        foreach (var item in items)
        {
            string? from = null;
            string? kind = null;
            string? fn = null;

            if (item.ValueKind == JsonValueKind.String)
            {
                from = NormalizeAddress(item.GetString() ?? "");
            }
            else if (item.ValueKind == JsonValueKind.Object)
            {
                from = GetString(item, "from", "from_address", "address", "caller", "source");
                fn = GetString(item, "from_function", "function", "name", "caller_name");
                kind = GetString(item, "type", "refKind", "ref_kind", "reference_type");
                if (from is not null)
                    from = NormalizeAddress(from);
            }

            if (string.IsNullOrWhiteSpace(from))
                continue;

            fn ??= await TryResolveFunctionNameAsync(from, ct);
            list.Add(new XrefEntry(from, fn, kind ?? "xref"));
        }

        return list;
    }

    private static ImportEntry? ParseImportLine(string line)
    {
        if (line.StartsWith("Error", StringComparison.OrdinalIgnoreCase))
            return null;

        var addr = ExtractAddress(line);
        if (addr is null)
            return null;

        var name = line;
        foreach (var sep in new[] { " @ ", " - ", "\t", "  " })
        {
            var idx = line.IndexOf(sep, StringComparison.Ordinal);
            if (idx > 0)
            {
                name = line[..idx].Trim();
                break;
            }
        }

        name = name.Trim().Trim('"', '\'');
        if (name.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return null;

        string? lib = null;
        var paren = name.IndexOf('(');
        if (paren > 0 && name.EndsWith(')'))
        {
            lib = name[(paren + 1)..^1];
            name = name[..paren];
        }
        else
        {
            var tail = line.IndexOf('(');
            if (tail > 0 && line.TrimEnd().EndsWith(')'))
            {
                var open = line.LastIndexOf('(');
                if (open > 0 && open < line.Length - 1)
                    lib = line[(open + 1)..^1].Trim();
            }
        }

        return new ImportEntry(name, lib, NormalizeAddress(addr));
    }

    private static string? ExtractAddress(string text)
    {
        var m = Regex.Match(text, @"(0x[0-9a-fA-F]+)", RegexOptions.CultureInvariant);
        return m.Success ? NormalizeAddress(m.Groups[1].Value) : null;
    }

    private static string NormalizeAddress(string address)
    {
        var s = address.Trim();
        if (!s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            s = "0x" + s;
        return s.ToLowerInvariant();
    }

    private static string? GetString(JsonElement obj, params string[] names)
    {
        foreach (var name in names)
        {
            if (obj.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String)
                return el.GetString();
        }
        return null;
    }

    private static string GuessRefKind(string line)
    {
        if (line.Contains("CALL", StringComparison.OrdinalIgnoreCase))
            return "call";
        if (line.Contains("DATA", StringComparison.OrdinalIgnoreCase))
            return "data";
        return "xref";
    }

    private static string? ExtractProgramName(string body)
    {
        var m = Regex.Match(body, @"program\s+'([^']+)'", RegexOptions.IgnoreCase);
        if (m.Success)
            return m.Groups[1].Value;
        m = Regex.Match(body, @"program\s+""([^""]+)""", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value : null;
    }

    private static async Task<string> GetTextAsync(string url, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        var token = Environment.GetEnvironmentVariable("GHIDRA_MCP_AUTH_TOKEN");
        if (!string.IsNullOrWhiteSpace(token))
            req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        using var resp = await Http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
        return await resp.Content.ReadAsStringAsync(ct);
    }
}
