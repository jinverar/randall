using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace Randall.Infrastructure;

/// <summary>
/// Optional shared-secret gate for <c>randall agent</c> / serve on a lab LAN.
/// Set <see cref="EnvToken"/> (or pass <c>--token</c> to serve/agent). Not multi-user IAM.
/// </summary>
public static class LabAccess
{
    public const string EnvToken = "RANDALL_AGENT_TOKEN";
    public const string HeaderName = "X-Randall-Token";
    public const string AgentProxyHeaderName = "X-Randall-Agent-Token";

    public static string? ConfiguredToken
    {
        get
        {
            var t = Environment.GetEnvironmentVariable(EnvToken);
            return string.IsNullOrWhiteSpace(t) ? null : t.Trim();
        }
    }

    public static bool IsConfigured => ConfiguredToken is not null;

    /// <summary>Attach token headers for outbound calls to a remote agent.</summary>
    public static void Apply(HttpRequestMessage request, string? token = null)
    {
        var t = string.IsNullOrWhiteSpace(token) ? ConfiguredToken : token.Trim();
        if (string.IsNullOrEmpty(t))
            return;

        if (!request.Headers.Contains(HeaderName))
            request.Headers.TryAddWithoutValidation(HeaderName, t);
        request.Headers.Authorization ??= new AuthenticationHeaderValue("Bearer", t);
    }

    /// <summary>True when presented token matches <see cref="ConfiguredToken"/> (or no token configured).</summary>
    public static bool MatchesConfigured(IEnumerable<string?> presented)
    {
        var expected = ConfiguredToken;
        if (expected is null)
            return true;

        foreach (var candidate in presented)
        {
            if (string.IsNullOrWhiteSpace(candidate))
                continue;
            if (FixedTimeEquals(candidate.Trim(), expected))
                return true;
        }

        return false;
    }

    public static IEnumerable<string> ExtractPresentedTokens(
        string? authorizationHeader,
        IEnumerable<string?>? xRandallTokens,
        string? queryToken)
    {
        if (!string.IsNullOrWhiteSpace(authorizationHeader) &&
            authorizationHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var bearer = authorizationHeader["Bearer ".Length..].Trim();
            if (bearer.Length > 0)
                yield return bearer;
        }

        if (xRandallTokens is not null)
        {
            foreach (var v in xRandallTokens)
            {
                if (!string.IsNullOrWhiteSpace(v))
                    yield return v.Trim();
            }
        }

        if (!string.IsNullOrWhiteSpace(queryToken))
            yield return queryToken.Trim();
    }

    private static bool FixedTimeEquals(string a, string b)
    {
        var ba = Encoding.UTF8.GetBytes(a);
        var bb = Encoding.UTF8.GetBytes(b);
        return ba.Length == bb.Length && CryptographicOperations.FixedTimeEquals(ba, bb);
    }
}
