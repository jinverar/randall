using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Randall.VulnFtp;

/// <summary>Minimal FTP lab server — boofuzz ftp_simple.py target. LAB USE ONLY.</summary>
internal static class Program
{
    private const string Banner = "220 Randall VulnFtp ready\r\n";

    public static int Main(string[] args)
    {
        
        var port = 2121;
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


        Console.WriteLine($"Randall VulnFtp listening on {host}:{port} (use --host 0.0.0.0 to expose all interfaces)");
        using var listener = new TcpListener(host, port);
        listener.Start();

        while (true)
        {
            try
            {
                var client = listener.AcceptTcpClient();
                _ = Task.Run(() => HandleClient(client));
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
                WriteAscii(stream, Banner);

                while (true)
                {
                    var line = ReadLine(stream);
                    if (line is null)
                        break;

                    var response = Dispatch(line);
                    WriteAscii(stream, response);
                    if (response.StartsWith("221"))
                        break;
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"client: {ex.Message}");
        }
    }

    private static string? ReadLine(NetworkStream stream)
    {
        using var ms = new MemoryStream();
        var buf = new byte[1];
        while (true)
        {
            var n = stream.Read(buf, 0, 1);
            if (n <= 0)
                return ms.Length == 0 ? null : Encoding.ASCII.GetString(ms.ToArray());
            ms.WriteByte(buf[0]);
            if (buf[0] == '\n')
                break;
            if (ms.Length > 8192)
                break;
        }
        return Encoding.ASCII.GetString(ms.ToArray()).TrimEnd('\r', '\n');
    }

    private static string Dispatch(string line)
    {
        if (line.StartsWith("USER ", StringComparison.OrdinalIgnoreCase))
        {
            VulnHandlers.User(line.AsSpan(5));
            return "331 Password required\r\n";
        }
        if (line.StartsWith("PASS ", StringComparison.OrdinalIgnoreCase))
        {
            VulnHandlers.Pass(line.AsSpan(5));
            return "230 Login OK\r\n";
        }
        if (line.StartsWith("CWD ", StringComparison.OrdinalIgnoreCase))
        {
            VulnHandlers.Path(line.AsSpan(4));
            return "250 CWD OK\r\n";
        }
        if (line.StartsWith("STOR ", StringComparison.OrdinalIgnoreCase))
        {
            VulnHandlers.Path(line.AsSpan(5));
            return "150 Opening data connection\r\n226 Transfer complete\r\n";
        }
        if (line.StartsWith("RETR ", StringComparison.OrdinalIgnoreCase))
        {
            VulnHandlers.Path(line.AsSpan(5));
            return "150 Opening data connection\r\n226 Transfer complete\r\n";
        }
        if (line.StartsWith("QUIT", StringComparison.OrdinalIgnoreCase))
            return "221 Goodbye\r\n";
        if (line.StartsWith("HELP", StringComparison.OrdinalIgnoreCase))
            return "214 USER PASS CWD STOR RETR QUIT\r\n";

        return "500 Unknown command\r\n";
    }

    private static void WriteAscii(NetworkStream stream, string text)
    {
        var bytes = Encoding.ASCII.GetBytes(text);
        stream.Write(bytes);
        stream.Flush();
    }
}

internal static unsafe class VulnHandlers
{
    public static void User(ReadOnlySpan<char> arg) => CopyOverflow(arg, 128);
    public static void Pass(ReadOnlySpan<char> arg) => CopyOverflow(arg, 128);
    public static void Path(ReadOnlySpan<char> arg) => CopyOverflow(arg, 200);

    private static void CopyOverflow(ReadOnlySpan<char> src, int stackSize)
    {
        var buf = stackalloc byte[stackSize];
        for (var i = 0; i < src.Length; i++)
            buf[i] = (byte)src[i];
    }
}
