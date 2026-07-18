using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>HTTP client for Target Runtime on a remote <c>randall agent</c>.</summary>
public static class TargetRuntimeClient
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    public static async Task<TargetRuntimeListDto> ListAsync(string agentUrl, CancellationToken ct = default)
    {
        var baseUrl = RequireBase(agentUrl);
        var list = await Http.GetFromJsonAsync<TargetRuntimeListDto>($"{baseUrl}/api/runtime", JsonOpts, ct)
                   ?? new TargetRuntimeListDto("?", []);
        return list;
    }

    public static async Task<TargetRuntimeStatusDto> StatusAsync(string agentUrl, string id, CancellationToken ct = default)
    {
        var baseUrl = RequireBase(agentUrl);
        var st = await Http.GetFromJsonAsync<TargetRuntimeStatusDto>(
            $"{baseUrl}/api/runtime/{Uri.EscapeDataString(id)}", JsonOpts, ct);
        return st ?? Fail(id, "Empty status response");
    }

    public static async Task<TargetRuntimeStatusDto> StartAsync(
        string agentUrl, TargetRuntimeStartRequest request, CancellationToken ct = default)
    {
        var baseUrl = RequireBase(agentUrl);
        using var resp = await Http.PostAsJsonAsync($"{baseUrl}/api/runtime/start", request, JsonOpts, ct);
        var body = await resp.Content.ReadFromJsonAsync<TargetRuntimeStatusDto>(JsonOpts, ct);
        if (body is null)
            return Fail(request.Id, $"Agent returned {resp.StatusCode}");
        return body;
    }

    public static async Task<TargetRuntimeStatusDto> StartFromProjectAsync(
        string agentUrl, string yamlPath, string? id = null, CancellationToken ct = default)
    {
        var baseUrl = RequireBase(agentUrl);
        var q = new StringBuilder($"{baseUrl}/api/runtime/start-project?yamlPath={Uri.EscapeDataString(yamlPath)}");
        if (!string.IsNullOrWhiteSpace(id))
            q.Append("&id=").Append(Uri.EscapeDataString(id));
        using var resp = await Http.PostAsync(q.ToString(), null, ct);
        var body = await resp.Content.ReadFromJsonAsync<TargetRuntimeStatusDto>(JsonOpts, ct);
        if (body is null)
            return Fail(id ?? yamlPath, $"Agent returned {resp.StatusCode}");
        return body;
    }

    public static async Task<TargetRuntimeStatusDto> StopAsync(string agentUrl, string id, CancellationToken ct = default)
    {
        var baseUrl = RequireBase(agentUrl);
        using var resp = await Http.PostAsync($"{baseUrl}/api/runtime/{Uri.EscapeDataString(id)}/stop", null, ct);
        var body = await resp.Content.ReadFromJsonAsync<TargetRuntimeStatusDto>(JsonOpts, ct);
        return body ?? Fail(id, $"Agent returned {resp.StatusCode}");
    }

    public static async Task<TargetRuntimeStatusDto> RestartAsync(string agentUrl, string id, CancellationToken ct = default)
    {
        var baseUrl = RequireBase(agentUrl);
        using var resp = await Http.PostAsync($"{baseUrl}/api/runtime/{Uri.EscapeDataString(id)}/restart", null, ct);
        var body = await resp.Content.ReadFromJsonAsync<TargetRuntimeStatusDto>(JsonOpts, ct);
        return body ?? Fail(id, $"Agent returned {resp.StatusCode}");
    }

    public static async Task<TargetRuntimeStatusDto> StopAllAsync(string agentUrl, CancellationToken ct = default)
    {
        var baseUrl = RequireBase(agentUrl);
        using var resp = await Http.PostAsync($"{baseUrl}/api/runtime/stop-all", null, ct);
        var body = await resp.Content.ReadFromJsonAsync<TargetRuntimeStatusDto>(JsonOpts, ct);
        return body ?? Fail("all", $"Agent returned {resp.StatusCode}");
    }

    public static async Task<MemoryLensReportDto> InspectAsync(
        string agentUrl, int pid, CancellationToken ct = default)
    {
        var baseUrl = RequireBase(agentUrl);
        var report = await Http.GetFromJsonAsync<MemoryLensReportDto>(
            $"{baseUrl}/api/runtime/inspect?pid={pid}", JsonOpts, ct);
        return report ?? new MemoryLensReportDto(
            false, null, pid, "unavailable", ["Empty inspect response"], null, [], [], [], null,
            "Empty inspect response");
    }

    private static string RequireBase(string agentUrl)
    {
        if (!LabAgentClient.TryNormalizeAgentUrl(agentUrl, out var baseUrl, out var err))
            throw new ArgumentException(err ?? "Invalid agent URL");
        return baseUrl;
    }

    private static TargetRuntimeStatusDto Fail(string id, string message) =>
        new(id, false, message, false, null, null, null, null,
            null, null, null, false, null, null, null, null, null);
}
