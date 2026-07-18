using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Randall.VulnHttp;

/// <summary>Minimal HTTP/1.1 lab server with intentional parser bugs. LAB USE ONLY.</summary>
internal static class Program
{
    public static int Main(string[] args)
    {
        
        var port = 8080;
        var host = IPAddress.Loopback;
        for (var i = 0; i < args.Length; i++)
        {
            if ((args[i] is "-p" or "--port") && i + 1 < args.Length && int.TryParse(args[i + 1], out var p))
            {
                port = p;
                i++;
            }
            else if ((args[i] is "-h" or "--host") && i + 1 < args.Length)
            {
                var h = args[++i];
                if (h is "0.0.0.0" or "*" or "any" or "all")
                    host = IPAddress.Any;
                else if (!IPAddress.TryParse(h, out host!))
                    host = IPAddress.Loopback;
            }
        }


        Console.WriteLine($"Randall VulnHttp listening on {host}:{port} (use --host 0.0.0.0 to expose all interfaces)");
        using var listener = new TcpListener(host, port);
        listener.Start();

        while (true)
        {
            try
            {
                var client = listener.AcceptTcpClient();
                HandleClient(client);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"accept: {ex.Message}");
            }
        }
    }

    private static void HandleClient(TcpClient client)
    {
        try
        {
            using (client)
            using (var stream = client.GetStream())
            {
                stream.ReadTimeout = 5000;
                var request = ReadRequest(stream);
                if (request.Length == 0)
                    return;

                var response = Dispatch(request);
                WriteAscii(stream, response);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"client: {ex.Message}");
        }
    }

    private static byte[] ReadRequest(NetworkStream stream)
    {
        using var ms = new MemoryStream();
        var buf = new byte[8192];
        while (stream.DataAvailable || ms.Length == 0)
        {
            int n;
            try { n = stream.Read(buf, 0, buf.Length); }
            catch { break; }
            if (n <= 0)
                break;
            ms.Write(buf, 0, n);
            if (ms.Length > 65536)
                break;
        }
        return ms.ToArray();
    }

    private static string Dispatch(byte[] raw)
    {
        var text = Encoding.ASCII.GetString(raw);
        var lines = text.Split("\r\n", StringSplitOptions.None);
        if (lines.Length == 0)
            return NotFound();

        var requestLine = lines[0];
        VulnHandlers.ParseRequestLine(requestLine);

        foreach (var line in lines.Skip(1))
        {
            if (line.Length == 0)
                break;
            if (line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                VulnHandlers.ParseHost(line);
            else if (line.StartsWith("User-Agent:", StringComparison.OrdinalIgnoreCase))
                VulnHandlers.ParseUserAgent(line);
            else if (line.StartsWith("Cookie:", StringComparison.OrdinalIgnoreCase))
                VulnHandlers.ParseCookie(line);
        }

        var bodyStart = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (bodyStart >= 0 && bodyStart + 4 < raw.Length)
            VulnHandlers.ParseBody(raw.AsSpan(bodyStart + 4));

        if (requestLine.StartsWith("GET ", StringComparison.OrdinalIgnoreCase))
            return OkHtml();
        if (requestLine.StartsWith("POST ", StringComparison.OrdinalIgnoreCase))
            return OkPlain("POST OK");

        return NotFound();
    }

    private static string OkHtml() =>
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 48\r\n\r\n" +
        "<html><body>Randall VulnHttp</body></html>";

    private static string OkPlain(string body)
    {
        return $"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\n\r\n{body}";
    }

    private static string NotFound() =>
        "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\n\r\nNot Found";

    private static void WriteAscii(NetworkStream stream, string text)
    {
        var bytes = Encoding.ASCII.GetBytes(text);
        stream.Write(bytes);
        stream.Flush();
    }
}

internal static unsafe class VulnHandlers
{
    public static void ParseRequestLine(string line)
    {
        var uriStart = line.IndexOf(' ');
        if (uriStart < 0)
            return;
        var uriEnd = line.IndexOf(' ', uriStart + 1);
        if (uriEnd < 0)
            uriEnd = line.Length;
        var uri = line.AsSpan(uriStart + 1, uriEnd - uriStart - 1);
        CopyOverflow(uri, 256);
    }

    public static void ParseHost(string line)
    {
        var val = line.AsSpan(5).Trim();
        CopyOverflow(val, 128);
    }

    public static void ParseUserAgent(string line)
    {
        var val = line.AsSpan(11).Trim();
        CopyOverflow(val, 160);
    }

    public static void ParseCookie(string line)
    {
        var val = line.AsSpan(7).Trim();
        CopyOverflow(val, 192);
    }

    public static void ParseBody(ReadOnlySpan<byte> body)
    {
        CopyOverflow(body, 512);
    }

    private static void CopyOverflow(ReadOnlySpan<char> src, int stackSize)
    {
        if (src.Length > stackSize)
            Environment.Exit(unchecked((int)0xC0000005));

        var buf = stackalloc byte[stackSize];
        for (var i = 0; i < src.Length; i++)
            buf[i] = (byte)src[i];
    }

    private static void CopyOverflow(ReadOnlySpan<byte> src, int stackSize)
    {
        if (src.Length > stackSize)
            Environment.Exit(unchecked((int)0xC0000005));

        var buf = stackalloc byte[stackSize];
        for (var i = 0; i < src.Length; i++)
            buf[i] = src[i];
    }
}
