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

    public static async Task<IReadOnlyList<LabServerInfoDto>> ListAsync(string agentUrl, CancellationToken ct = default)
    {
        if (!TryNormalizeAgentUrl(agentUrl, out var baseUrl, out var err))
            throw new ArgumentException(err);
        var list = await Http.GetFromJsonAsync<List<LabServerInfoDto>>($"{baseUrl}/api/labs", JsonOpts, ct)
                   ?? [];
        return list;
    }

    public static async Task<LabServerActionResultDto> StartAsync(string agentUrl, string id, CancellationToken ct = default)
    {
        if (!TryNormalizeAgentUrl(agentUrl, out var baseUrl, out var err))
            throw new ArgumentException(err);
        using var resp = await Http.PostAsync($"{baseUrl}/api/labs/{Uri.EscapeDataString(id)}/start", null, ct);
        var body = await resp.Content.ReadFromJsonAsync<LabServerActionResultDto>(JsonOpts, ct);
        if (body is null)
            throw new InvalidOperationException($"Agent returned {resp.StatusCode}");
        return body;
    }

    public static async Task<LabServerActionResultDto> StopAsync(string agentUrl, string id, CancellationToken ct = default)
    {
        if (!TryNormalizeAgentUrl(agentUrl, out var baseUrl, out var err))
            throw new ArgumentException(err);
        using var resp = await Http.PostAsync($"{baseUrl}/api/labs/{Uri.EscapeDataString(id)}/stop", null, ct);
        var body = await resp.Content.ReadFromJsonAsync<LabServerActionResultDto>(JsonOpts, ct);
        if (body is null)
            throw new InvalidOperationException($"Agent returned {resp.StatusCode}");
        return body;
    }

    public static async Task<LabServerActionResultDto> StopAllAsync(string agentUrl, CancellationToken ct = default)
    {
        if (!TryNormalizeAgentUrl(agentUrl, out var baseUrl, out var err))
            throw new ArgumentException(err);
        using var resp = await Http.PostAsync($"{baseUrl}/api/labs/stop-all", null, ct);
        var body = await resp.Content.ReadFromJsonAsync<LabServerActionResultDto>(JsonOpts, ct);
        if (body is null)
            throw new InvalidOperationException($"Agent returned {resp.StatusCode}");
        return body;
    }

    public static async Task<LabAgentPingDto> PingAsync(string agentUrl, CancellationToken ct = default)
    {
        if (!TryNormalizeAgentUrl(agentUrl, out var baseUrl, out var err))
            throw new ArgumentException(err);
        var health = await Http.GetFromJsonAsync<HealthDto>($"{baseUrl}/api/health", JsonOpts, ct)
                     ?? throw new InvalidOperationException("No health response");
        return new LabAgentPingDto(true, baseUrl, health.Name, health.Version, new Uri(baseUrl).Host);
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
    string? LocalMachine);
