using System.Text;

namespace Randall.Infrastructure;

/// <summary>Leg 3 — Send: validate server responses during session flows (boofuzz s_switch lite).</summary>
public static class ResponseMatcher
{
    public static bool Matches(byte[]? response, string? expectPattern)
    {
        if (string.IsNullOrWhiteSpace(expectPattern))
            return true;
        if (response is null || response.Length == 0)
            return false;

        var text = Encoding.ASCII.GetString(response);
        return text.Contains(expectPattern, StringComparison.OrdinalIgnoreCase);
    }

    public static string Describe(byte[]? response, int maxLen = 120)
    {
        if (response is null || response.Length == 0)
            return "(no response)";
        var text = Encoding.ASCII.GetString(response);
        text = text.Replace("\r", "\\r").Replace("\n", "\\n");
        return text.Length <= maxLen ? text : text[..maxLen] + "…";
    }
}
