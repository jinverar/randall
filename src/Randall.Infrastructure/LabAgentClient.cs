using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Proxy lab start/stop/status to a remote <c>randall agent</c> (same /api/labs endpoints).
/// No kernel driver — the agent process on the lab box owns the vuln servers.
/// </summary>
public static class LabAgentClient
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(15) };
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    public static bool TryNormalizeAgentUrl(string? raw, out string baseUrl, out string? error)
    {
        baseUrl = "";
        error = null;
        if (string.IsNullOrWhiteSpace(raw))
        {
            error = "agent URL required";
            return false;
        }

        var s = raw.Trim().TrimEnd('/');
        if (!s.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !s.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            s = "http://" + s;

        if (!Uri.TryCreate(s, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            error = "Invalid agent URL";
            return false;
        }

        if (!IsAllowedAgentHost(uri.Host))
        {
            error = "Agent host must be localhost or a private LAN address (not the public internet).";
            return false;
        }

        baseUrl = uri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
        return true;
    }

    public static async Task<IReadOnlyList<LabServerInfoDto>> ListAsync(
        string agentUrl, string? token = null, string? category = null, CancellationToken ct = default)
    {
        if (!TryNormalizeAgentUrl(agentUrl, out var baseUrl, out var err))
            throw new ArgumentException(err);
        var path = $"{baseUrl}/api/labs";
        if (!string.IsNullOrWhiteSpace(category) && !category.Equals("all", StringComparison.OrdinalIgnoreCase))
            path += $"?category={Uri.EscapeDataString(category.Trim())}";
        using var req = new HttpRequestMessage(HttpMethod.Get, path);
        LabAccess.Apply(req, token);
        using var resp = await Http.SendAsync(req, ct);
        await EnsureSuccess(resp, ct);
        var list = await resp.Content.ReadFromJsonAsync<List<LabServerInfoDto>>(JsonOpts, ct) ?? [];
        return list;
    }

    public static async Task<LabServerActionResultDto> StartAsync(
        string agentUrl, string id, string? token = null, CancellationToken ct = default)
    {
        if (!TryNormalizeAgentUrl(agentUrl, out var baseUrl, out var err))
            throw new ArgumentException(err);
        using var req = new HttpRequestMessage(
            HttpMethod.Post, $"{baseUrl}/api/labs/{Uri.EscapeDataString(id)}/start");
        LabAccess.Apply(req, token);
        using var resp = await Http.SendAsync(req, ct);
        var body = await resp.Content.ReadFromJsonAsync<LabServerActionResultDto>(JsonOpts, ct);
        if (body is null)
            throw new InvalidOperationException($"Agent returned {resp.StatusCode}");
        return body;
    }

    public static async Task<LabServerActionResultDto> StopAsync(
        string agentUrl, string id, string? token = null, CancellationToken ct = default)
    {
        if (!TryNormalizeAgentUrl(agentUrl, out var baseUrl, out var err))
            throw new ArgumentException(err);
        using var req = new HttpRequestMessage(
            HttpMethod.Post, $"{baseUrl}/api/labs/{Uri.EscapeDataString(id)}/stop");
        LabAccess.Apply(req, token);
        using var resp = await Http.SendAsync(req, ct);
        var body = await resp.Content.ReadFromJsonAsync<LabServerActionResultDto>(JsonOpts, ct);
        if (body is null)
            throw new InvalidOperationException($"Agent returned {resp.StatusCode}");
        return body;
    }

    public static async Task<LabServerActionResultDto> StopAllAsync(
        string agentUrl, string? token = null, CancellationToken ct = default)
    {
        if (!TryNormalizeAgentUrl(agentUrl, out var baseUrl, out var err))
            throw new ArgumentException(err);
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/api/labs/stop-all");
        LabAccess.Apply(req, token);
        using var resp = await Http.SendAsync(req, ct);
        var body = await resp.Content.ReadFromJsonAsync<LabServerActionResultDto>(JsonOpts, ct);
        if (body is null)
            throw new InvalidOperationException($"Agent returned {resp.StatusCode}");
        return body;
    }

    public static async Task<LabAgentPingDto> PingAsync(
        string agentUrl, string? token = null, CancellationToken ct = default)
    {
        if (!TryNormalizeAgentUrl(agentUrl, out var baseUrl, out var err))
            throw new ArgumentException(err);
        using var req = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/api/health");
        // Health is open even when a token is configured — still send token for future use.
        LabAccess.Apply(req, token);
        using var resp = await Http.SendAsync(req, ct);
        await EnsureSuccess(resp, ct);
        var health = await resp.Content.ReadFromJsonAsync<HealthDto>(JsonOpts, ct)
                     ?? throw new InvalidOperationException("No health response");
        return new LabAgentPingDto(true, baseUrl, health.Name, health.Version, new Uri(baseUrl).Host,
            health.AuthRequired);
    }

    private static async Task EnsureSuccess(HttpResponseMessage resp, CancellationToken ct)
    {
        if (resp.IsSuccessStatusCode)
            return;
        var body = await resp.Content.ReadAsStringAsync(ct);
        throw new InvalidOperationException(
            resp.StatusCode == HttpStatusCode.Unauthorized
                ? "Agent requires RANDALL_AGENT_TOKEN (set env, --token, or UI agent token)."
                : $"Agent returned {(int)resp.StatusCode}: {body}");
    }

    private static bool IsAllowedAgentHost(string host)
    {
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            host.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase) ||
            host.Equals("::1", StringComparison.OrdinalIgnoreCase))
            return true;

        if (!IPAddress.TryParse(host, out var ip))
            return false; // hostnames other than localhost blocked for MVP

        if (IPAddress.IsLoopback(ip))
            return true;

        var bytes = ip.GetAddressBytes();
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && bytes.Length == 4)
        {
            // 10/8, 172.16/12, 192.168/16
            if (bytes[0] == 10) return true;
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
        }

        return false;
    }
}

public sealed record LabAgentPingDto(
    bool Ok,
    string AgentUrl,
    string? AppName,
    string? Version,
    string? LocalMachine,
    bool AuthRequired = false);
