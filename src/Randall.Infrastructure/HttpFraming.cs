using System.Text;
using System.Text.RegularExpressions;

namespace Randall.Infrastructure;

/// <summary>
/// HTTP/1.x helpers for web-app fuzzing — keep Content-Length honest after body mutations
/// (same role as <see cref="NbssFraming"/> for SMB).
/// </summary>
public static partial class HttpFraming
{
    /// <summary>
    /// If the message looks like HTTP/1.x with a body, rewrite Content-Length to match
    /// the bytes after the header terminator. Skips when Content-Length is absent/chunked.
    /// </summary>
    public static byte[] TrySyncContentLength(byte[] message)
    {
        if (message.Length < 16)
            return message;

        var sep = IndexOfHeaderBodySep(message);
        if (sep < 0)
            return message;

        var headerBytes = message.AsSpan(0, sep);
        var bodyLen = message.Length - sep;
        var header = Encoding.ASCII.GetString(headerBytes);

        // Don't touch chunked encodings.
        if (TransferEncodingChunkedRegex().IsMatch(header))
            return message;

        if (!ContentLengthLineRegex().IsMatch(header))
            return message;

        var newHeader = ContentLengthLineRegex().Replace(
            header,
            m => $"{m.Groups[1].Value}{bodyLen}{m.Groups[3].Value}",
            1);

        var hdr = Encoding.ASCII.GetBytes(newHeader);
        var result = new byte[hdr.Length + bodyLen];
        hdr.CopyTo(result, 0);
        if (bodyLen > 0)
            Buffer.BlockCopy(message, sep, result, hdr.Length, bodyLen);
        return result;
    }

    public static bool LooksLikeHttpRequest(ReadOnlySpan<byte> message)
    {
        if (message.Length < 4)
            return false;
        // GET / POST / HEAD / PUT / …
        return (message[0] is (byte)'G' or (byte)'P' or (byte)'H' or (byte)'D' or (byte)'O' or (byte)'T' or (byte)'C')
               && message.IndexOf("HTTP/"u8) >= 0;
    }

    public static bool TryParseStatusCode(ReadOnlySpan<byte> response, out int status)
    {
        status = 0;
        if (response.Length < 12)
            return false;
        var text = Encoding.ASCII.GetString(response);
        var m = HttpStatusRegex().Match(text);
        if (!m.Success)
            return false;
        return int.TryParse(m.Groups[1].Value, out status);
    }

    public static string StatusClass(byte[]? response)
    {
        if (response is null || response.Length == 0)
            return "empty";
        if (!TryParseStatusCode(response, out var code))
            return "non-http";
        return code switch
        {
            >= 100 and < 200 => "1xx",
            >= 200 and < 300 => "2xx",
            >= 300 and < 400 => "3xx",
            >= 400 and < 500 => "4xx",
            >= 500 and < 600 => "5xx",
            _ => $"http-{code}",
        };
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

    [GeneratedRegex(@"(?im)^(Content-Length:\s*)(\d+)(\r?)$", RegexOptions.Multiline)]
    private static partial Regex ContentLengthLineRegex();

    [GeneratedRegex(@"(?im)^Transfer-Encoding:\s*chunked\b", RegexOptions.Multiline)]
    private static partial Regex TransferEncodingChunkedRegex();

    [GeneratedRegex(@"^HTTP/\d\.\d\s+(\d{3})\b", RegexOptions.Multiline)]
    private static partial Regex HttpStatusRegex();
}
