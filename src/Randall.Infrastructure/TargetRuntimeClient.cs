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

    public static async Task<TargetRuntimeListDto> ListAsync(
        string agentUrl, string? token = null, CancellationToken ct = default)
    {
        var baseUrl = RequireBase(agentUrl);
        using var req = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/api/runtime");
        LabAccess.Apply(req, token);
        using var resp = await Http.SendAsync(req, ct);
        var list = await resp.Content.ReadFromJsonAsync<TargetRuntimeListDto>(JsonOpts, ct)
                   ?? new TargetRuntimeListDto("?", []);
        return list;
    }

    public static async Task<TargetRuntimeStatusDto> StatusAsync(
        string agentUrl, string id, string? token = null, CancellationToken ct = default)
    {
        var baseUrl = RequireBase(agentUrl);
        using var req = new HttpRequestMessage(
            HttpMethod.Get, $"{baseUrl}/api/runtime/{Uri.EscapeDataString(id)}");
        LabAccess.Apply(req, token);
        using var resp = await Http.SendAsync(req, ct);
        var st = await resp.Content.ReadFromJsonAsync<TargetRuntimeStatusDto>(JsonOpts, ct);
        return st ?? Fail(id, "Empty status response");
    }

    public static async Task<TargetRuntimeStatusDto> StartAsync(
        string agentUrl, TargetRuntimeStartRequest request, string? token = null,
        CancellationToken ct = default)
    {
        var baseUrl = RequireBase(agentUrl);
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/runtime/start")
        {
            Content = JsonContent.Create(request, options: JsonOpts),
        };
        LabAccess.Apply(req, token);
        using var resp = await Http.SendAsync(req, ct);
        var body = await resp.Content.ReadFromJsonAsync<TargetRuntimeStatusDto>(JsonOpts, ct);
        if (body is null)
            return Fail(request.Id, $"Agent returned {resp.StatusCode}");
        return body;
    }

    public static async Task<TargetRuntimeStatusDto> StartFromProjectAsync(
        string agentUrl, string yamlPath, string? id = null, string? token = null,
        CancellationToken ct = default)
    {
        var baseUrl = RequireBase(agentUrl);
        var q = new StringBuilder($"{baseUrl}/api/runtime/start-project?yamlPath={Uri.EscapeDataString(yamlPath)}");
        if (!string.IsNullOrWhiteSpace(id))
            q.Append("&id=").Append(Uri.EscapeDataString(id));
        using var req = new HttpRequestMessage(HttpMethod.Post, q.ToString());
        LabAccess.Apply(req, token);
        using var resp = await Http.SendAsync(req, ct);
        var body = await resp.Content.ReadFromJsonAsync<TargetRuntimeStatusDto>(JsonOpts, ct);
        if (body is null)
            return Fail(id ?? yamlPath, $"Agent returned {resp.StatusCode}");
        return body;
    }

    public static async Task<TargetRuntimeStatusDto> StopAsync(
        string agentUrl, string id, string? token = null, CancellationToken ct = default)
    {
        var baseUrl = RequireBase(agentUrl);
        using var req = new HttpRequestMessage(
            HttpMethod.Post, $"{baseUrl}/api/runtime/{Uri.EscapeDataString(id)}/stop");
        LabAccess.Apply(req, token);
        using var resp = await Http.SendAsync(req, ct);
        var body = await resp.Content.ReadFromJsonAsync<TargetRuntimeStatusDto>(JsonOpts, ct);
        return body ?? Fail(id, $"Agent returned {resp.StatusCode}");
    }

    public static async Task<TargetRuntimeStatusDto> RestartAsync(
        string agentUrl, string id, string? token = null, CancellationToken ct = default)
    {
        var baseUrl = RequireBase(agentUrl);
        using var req = new HttpRequestMessage(
            HttpMethod.Post, $"{baseUrl}/api/runtime/{Uri.EscapeDataString(id)}/restart");
        LabAccess.Apply(req, token);
        using var resp = await Http.SendAsync(req, ct);
        var body = await resp.Content.ReadFromJsonAsync<TargetRuntimeStatusDto>(JsonOpts, ct);
        return body ?? Fail(id, $"Agent returned {resp.StatusCode}");
    }

    public static async Task<TargetRuntimeStatusDto> StopAllAsync(
        string agentUrl, string? token = null, CancellationToken ct = default)
    {
        var baseUrl = RequireBase(agentUrl);
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/runtime/stop-all");
        LabAccess.Apply(req, token);
        using var resp = await Http.SendAsync(req, ct);
        var body = await resp.Content.ReadFromJsonAsync<TargetRuntimeStatusDto>(JsonOpts, ct);
        return body ?? Fail("all", $"Agent returned {resp.StatusCode}");
    }

    public static async Task<MemoryLensReportDto> InspectAsync(
        string agentUrl, int pid, string? token = null, CancellationToken ct = default)
    {
        var baseUrl = RequireBase(agentUrl);
        using var req = new HttpRequestMessage(
            HttpMethod.Get, $"{baseUrl}/api/runtime/inspect?pid={pid}");
        LabAccess.Apply(req, token);
        using var resp = await Http.SendAsync(req, ct);
        var report = await resp.Content.ReadFromJsonAsync<MemoryLensReportDto>(JsonOpts, ct);
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
