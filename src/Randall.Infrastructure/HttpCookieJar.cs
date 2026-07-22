using System.Text;
using System.Text.RegularExpressions;

namespace Randall.Infrastructure;

/// <summary>
/// Minimal HTTP/1.x cookie jar for web-app fuzzing — absorb Set-Cookie from responses
/// and inject a Cookie header on outbound requests. Not a full browser jar (no Path/Domain
/// expiry / Secure / SameSite enforcement). Opt-in via <c>fuzz.syncCookies</c> or auto for http/https.
/// </summary>
public static partial class HttpCookieJar
{
    /// <summary>Parse Set-Cookie headers and merge name=value pairs into <paramref name="jar"/>.</summary>
    public static void AbsorbSetCookie(IDictionary<string, string> jar, byte[]? response)
    {
        if (response is null || response.Length == 0 || jar is null)
            return;

        var text = Encoding.ASCII.GetString(response);
        foreach (Match m in SetCookieRegex().Matches(text))
        {
            var pair = m.Groups[1].Value.Trim();
            var eq = pair.IndexOf('=');
            if (eq <= 0)
                continue;
            var name = pair[..eq].Trim();
            var value = pair[(eq + 1)..].Trim();
            if (name.Length == 0)
                continue;
            // Strip attributes after first ;
            var semi = value.IndexOf(';');
            if (semi >= 0)
                value = value[..semi].Trim();
            jar[name] = value;
        }
    }

    /// <summary>
    /// Insert or replace a Cookie header with the jar contents. Returns the same instance
    /// when the jar is empty or the message is not an HTTP request.
    /// </summary>
    public static byte[] ApplyCookieHeader(byte[] request, IReadOnlyDictionary<string, string> jar)
    {
        if (jar is null || jar.Count == 0 || request.Length < 16)
            return request;
        if (!HttpFraming.LooksLikeHttpRequest(request))
            return request;

        var sep = IndexOfHeaderBodySep(request);
        if (sep < 0)
            return request;

        var header = Encoding.ASCII.GetString(request.AsSpan(0, sep));
        var cookieLine = "Cookie: " + string.Join("; ", jar.Select(kv => $"{kv.Key}={kv.Value}"));

        string newHeader;
        if (CookieHeaderRegex().IsMatch(header))
        {
            newHeader = CookieHeaderRegex().Replace(header, cookieLine + "\r\n", 1);
        }
        else
        {
            // Insert before the blank line terminator (header already includes trailing \r\n\r\n via sep).
            // sep points past \r\n\r\n; header string includes those four bytes as the last chars.
            if (header.EndsWith("\r\n\r\n", StringComparison.Ordinal))
                newHeader = header[..^2] + cookieLine + "\r\n\r\n";
            else
                newHeader = header.TrimEnd() + "\r\n" + cookieLine + "\r\n\r\n";
        }

        var hdr = Encoding.ASCII.GetBytes(newHeader);
        var bodyLen = request.Length - sep;
        var result = new byte[hdr.Length + bodyLen];
        hdr.CopyTo(result, 0);
        if (bodyLen > 0)
            Buffer.BlockCopy(request, sep, result, hdr.Length, bodyLen);
        return result;
    }

    private static int IndexOfHeaderBodySep(byte[] message)
    {
        for (var i = 0; i + 3 < message.Length; i++)
        {
            if (message[i] == (byte)'\r' && message[i + 1] == (byte)'\n' &&
                message[i + 2] == (byte)'\r' && message[i + 3] == (byte)'\n')
                return i + 4;
        }
        return -1;
    }

    [GeneratedRegex(@"(?im)^Set-Cookie:\s*([^\r\n]+)", RegexOptions.Multiline)]
    private static partial Regex SetCookieRegex();

    [GeneratedRegex(@"(?im)^Cookie:\s*[^\r\n]*\r?\n", RegexOptions.Multiline)]
    private static partial Regex CookieHeaderRegex();
}
