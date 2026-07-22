using Randall.Infrastructure;

namespace Randall.Server;

/// <summary>ASP.NET adapters for <see cref="LabAccess"/> (keeps Infrastructure free of AspNetCore refs).</summary>
public static class LabAccessHttp
{
    public static bool IsAuthorized(HttpRequest request)
    {
        request.Headers.TryGetValue(LabAccess.HeaderName, out var hdr);
        var query = request.Query.TryGetValue("token", out var q) ? q.ToString() : null;
        return LabAccess.MatchesConfigured(
            LabAccess.ExtractPresentedTokens(request.Headers.Authorization.ToString(), hdr, query));
    }

    public static string? ResolveOutboundAgentToken(HttpRequest request, string? agentTokenQuery = null)
    {
        if (!string.IsNullOrWhiteSpace(agentTokenQuery))
            return agentTokenQuery.Trim();

        if (request.Headers.TryGetValue(LabAccess.AgentProxyHeaderName, out var hdr))
        {
            var v = hdr.FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(v))
                return v.Trim();
        }

        return LabAccess.ConfiguredToken;
    }
}
