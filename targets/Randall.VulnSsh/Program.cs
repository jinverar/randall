using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Randall.VulnSsh;

/// <summary>
/// Fake SSH plaintext lab server — NOT real crypto. Banner + KEX stub + exec channel for fuzzing.
/// LAB USE ONLY.
/// </summary>
internal static class Program
{
    private const string Banner = "SSH-2.0-RandallVuln_1.0\r\n";

    public static int Main(string[] args)
    {
        
        var port = 2222;
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


        Console.WriteLine($"Randall VulnSsh (stub) listening on {host}:{port} (use --host 0.0.0.0 to expose all interfaces)");
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

                var clientBanner = ReadLine(stream);
                if (clientBanner is not null)
                    VulnHandlers.ClientVersion(clientBanner);

                while (true)
                {
                    var packet = ReadPacket(stream);
                    if (packet.Length == 0)
                        break;

                    if (packet.AsSpan().IndexOf("exec"u8) >= 0 ||
                        packet.AsSpan().IndexOf("shell"u8) >= 0)
                    {
                        VulnHandlers.ExecPayload(packet);
                        WriteAscii(stream, "OK\r\n");
                    }
                    else
                    {
                        WriteAscii(stream, "SSH_MSG_IGNORE\r\n");
                    }
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
        }
        return Encoding.ASCII.GetString(ms.ToArray()).TrimEnd('\r', '\n');
    }

    private static byte[] ReadPacket(NetworkStream stream)
    {
        using var ms = new MemoryStream();
        var buf = new byte[4096];
        try
        {
            while (stream.DataAvailable || ms.Length == 0)
            {
                var n = stream.Read(buf, 0, buf.Length);
                if (n <= 0)
                    break;
                ms.Write(buf, 0, n);
                if (ms.Length > 16384)
                    break;
            }
        }
        catch { /* timeout */ }
        return ms.ToArray();
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
    public static void ClientVersion(string version) =>
        CopyOverflow(version.AsSpan(), 128);

    public static void ExecPayload(byte[] data) =>
        CopyOverflow(data, 256);

    private static void CopyOverflow(ReadOnlySpan<char> src, int stackSize)
    {
        var buf = stackalloc byte[stackSize];
        for (var i = 0; i < src.Length; i++)
            buf[i] = (byte)src[i];
    }

    private static void CopyOverflow(byte[] src, int stackSize)
    {
        var buf = stackalloc byte[stackSize];
        for (var i = 0; i < src.Length; i++)
            buf[i] = src[i];
    }
}
