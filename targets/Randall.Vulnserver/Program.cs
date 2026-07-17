using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Randall.Vulnserver;

/// <summary>
/// Randall lab TCP server — vulnserver-compatible command surface with intentional bugs.
/// FOR AUTHORIZED LOCAL FUZZING ONLY.
/// </summary>
internal static class Program
{
    private const string Banner =
        "Welcome to Randall Vulnserver!\r\n" +
        "Master of camouflage. Competitive scarer.\r\n" +
        "Stalk code paths. Scream on crash.\r\n" +
        "Type HELP for commands.\r\n";

    public static int Main(string[] args)
    {
        var port = 9999;
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i] is "-p" or "--port" && int.TryParse(args[i + 1], out var p))
                port = p;
        }

        Console.WriteLine($"Randall Vulnserver listening on 0.0.0.0:{port}");
        using var listener = new TcpListener(IPAddress.Any, port);
        listener.Start();

        while (true)
        {
            TcpClient client;
            try
            {
                client = listener.AcceptTcpClient();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"accept failed: {ex.Message}");
                continue;
            }

            HandleClient(client);
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
                stream.WriteTimeout = 5000;
                WriteAscii(stream, Banner);

                var buffer = ReadAll(stream);
                if (buffer.Length == 0)
                    return;

                var response = Dispatch(buffer);
                if (response is not null)
                    WriteAscii(stream, response);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"client error: {ex.Message}");
        }
    }

    private static byte[] ReadAll(NetworkStream stream)
    {
        using var ms = new MemoryStream();
        var buf = new byte[8192];
        stream.ReadTimeout = 800;
        var idleRounds = 0;
        while (idleRounds < 6)
        {
            try
            {
                if (!stream.DataAvailable)
                {
                    Thread.Sleep(40);
                    idleRounds++;
                    continue;
                }

                idleRounds = 0;
                var n = stream.Read(buf, 0, buf.Length);
                if (n <= 0)
                    break;
                ms.Write(buf, 0, n);
            }
            catch (IOException)
            {
                break;
            }
        }

        if (ms.Length == 0)
        {
            try
            {
                var n = stream.Read(buf, 0, buf.Length);
                if (n > 0)
                    ms.Write(buf, 0, n);
            }
            catch { /* timeout ok */ }
        }

        return ms.ToArray();
    }

    private static string? Dispatch(ReadOnlySpan<byte> data)
    {
        var text = Encoding.ASCII.GetString(data);
        if (text.StartsWith("HELP", StringComparison.OrdinalIgnoreCase))
            return HelpText();

        if (text.StartsWith("STATS", StringComparison.OrdinalIgnoreCase) ||
            text.StartsWith("STAT", StringComparison.OrdinalIgnoreCase))
            return "STAT OK\r\nRandall fuzz stats: iterations=0 crashes=0\r\n";

        if (text.StartsWith("TRUN /.:/", StringComparison.OrdinalIgnoreCase))
        {
            VulnHandlers.Trun(data);
            return "TRUN OK\r\n";
        }

        if (text.StartsWith("GMON /.:/", StringComparison.OrdinalIgnoreCase) ||
            text.StartsWith("GMON ", StringComparison.OrdinalIgnoreCase))
        {
            VulnHandlers.Gmon(data);
            return "GMON OK\r\n";
        }

        if (text.StartsWith("GTER ", StringComparison.OrdinalIgnoreCase))
        {
            VulnHandlers.Gter(data);
            return "GTER OK\r\n";
        }

        if (text.StartsWith("KSTET /.:/", StringComparison.OrdinalIgnoreCase))
        {
            VulnHandlers.Kstet(data);
            return "KSTET OK\r\n";
        }

        if (text.StartsWith("HTER /.:/", StringComparison.OrdinalIgnoreCase))
        {
            VulnHandlers.Hter(data);
            return "HTER OK\r\n";
        }

        if (text.StartsWith("RAND ", StringComparison.OrdinalIgnoreCase))
        {
            VulnHandlers.Rand(data);
            return "RAND OK — eight legs, zero mercy.\r\n";
        }

        return "UNKNOWN COMMAND\r\n";
    }

    private static string HelpText() =>
        "Valid commands:\r\n" +
        "HELP\r\n" +
        "STATS / STAT\r\n" +
        "TRUN /.:/<payload>\r\n" +
        "GMON /.:/<payload>\r\n" +
        "GTER <payload>\r\n" +
        "KSTET /.:/<payload>\r\n" +
        "HTER /.:/<payload>\r\n" +
        "RAND <payload>\r\n";

    private static void WriteAscii(NetworkStream stream, string text)
    {
        var bytes = Encoding.ASCII.GetBytes(text);
        stream.Write(bytes);
        stream.Flush();
    }
}

internal static unsafe class VulnHandlers
{
    /// <summary>Classic TRUN stack smash — ~2000+ byte payload.</summary>
    public static void Trun(ReadOnlySpan<byte> data)
    {
        var payload = PayloadAfter(data, "TRUN /.:/");
        CopyOverflow(payload, stackSize: 256);
    }

    public static void Gmon(ReadOnlySpan<byte> data)
    {
        var payload = data.StartsWith("GMON /.:/"u8)
            ? PayloadAfter(data, "GMON /.:/")
            : PayloadAfter(data, "GMON ");
        CopyOverflow(payload, stackSize: 200);
    }

    public static void Gter(ReadOnlySpan<byte> data)
    {
        var payload = PayloadAfter(data, "GTER ");
        CopyOverflow(payload, stackSize: 128);
    }

    public static void Kstet(ReadOnlySpan<byte> data)
    {
        var payload = PayloadAfter(data, "KSTET /.:/");
        CopyOverflow(payload, stackSize: 180);
    }

    public static void Hter(ReadOnlySpan<byte> data)
    {
        var payload = PayloadAfter(data, "HTER /.:/");
        CopyOverflow(payload, stackSize: 160);
    }

    public static void Rand(ReadOnlySpan<byte> data)
    {
        var payload = PayloadAfter(data, "RAND ");
        CopyOverflow(payload, stackSize: 192);
    }

    private static ReadOnlySpan<byte> PayloadAfter(ReadOnlySpan<byte> data, string prefix)
    {
        var prefixBytes = Encoding.ASCII.GetBytes(prefix);
        if (data.Length <= prefixBytes.Length)
            return ReadOnlySpan<byte>.Empty;
        return data[prefixBytes.Length..];
    }

    private static void CopyOverflow(ReadOnlySpan<byte> src, int stackSize)
    {
        // Lab target: kill the whole process so Randall's ProcessMonitor detects the crash.
        // Use explicit exit code (not FailFast) so minidump capture can open the process.
        if (src.Length > stackSize)
            Environment.Exit(unchecked((int)0xC0000005));

        var buf = stackalloc byte[stackSize];
        for (var i = 0; i < src.Length; i++)
            buf[i] = src[i];
    }
}
