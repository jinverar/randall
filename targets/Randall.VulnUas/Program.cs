using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Randall.VulnUas;

/// <summary>
/// Fictional UAS1 tactical-link lab (status / route / sensor-bay parsers with intentional length bugs).
/// NOT a real UAS, GCS, or weaponized drone stack — no RF, arming, munitions, or vehicle control.
/// Distinct from RDL1 VulnDrone. LAB USE ONLY — loopback by default.
/// </summary>
internal static class Program
{
    private const int CrashExit = 139;

    private const byte TypeHello = 0x01;
    private const byte TypeRoute = 0x02;
    private const byte TypeSensor = 0x03;
    private const byte TypeTask = 0x04;

    private const byte TelemNav = 0x20;
    private const byte TelemLink = 0x21;
    private const byte TelemBay = 0x2F;

    public static int Main(string[] args)
    {
        var port = 15650;
        var host = IPAddress.Loopback;
        var mode = "tcp";

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
            else if ((args[i] is "-m" or "--mode") && i + 1 < args.Length)
            {
                mode = args[++i].Trim().ToLowerInvariant();
            }
        }

        if (mode is "udp" or "telem" or "telemetry")
        {
            if (port == 15650)
                port = 15651;
            RunUdp(host, port);
        }
        else
        {
            RunTcp(host, port);
        }

        return 0;
    }

    private static void RunTcp(IPAddress host, int port)
    {
        Console.WriteLine($"Randall VulnUas UAS1 tactical TCP on {host}:{port} (lab only; not a real UAS)");
        using var listener = new TcpListener(host, port);
        listener.Start();

        while (true)
        {
            try
            {
                using var client = listener.AcceptTcpClient();
                using var stream = client.GetStream();
                stream.ReadTimeout = 5000;
                WriteAscii(stream, "UAS1 LINK READY\r\n");
                HandleTcpSession(stream);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"tcp: {ex.Message}");
            }
        }
    }

    private static void RunUdp(IPAddress host, int port)
    {
        Console.WriteLine($"Randall VulnUas UAS1 telemetry UDP on {host}:{port} (lab only; not a real UAS)");
        using var client = host.Equals(IPAddress.Any)
            ? new UdpClient(port)
            : new UdpClient(new IPEndPoint(host, port));

        while (true)
        {
            try
            {
                var remote = new IPEndPoint(IPAddress.Any, 0);
                var data = client.Receive(ref remote);
                if (data.Length > 0)
                    HandleUdp(data);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"udp: {ex.Message}");
            }
        }
    }

    private static void HandleTcpSession(NetworkStream stream)
    {
        while (true)
        {
            if (!TryReadPacket(stream, out var type, out var body))
                return;

            switch (type)
            {
                case TypeHello:
                    HandleHello(body);
                    WriteAscii(stream, "HELLO OK\r\n");
                    break;
                case TypeRoute:
                    HandleRoute(body);
                    WriteAscii(stream, "ROUTE OK\r\n");
                    break;
                case TypeSensor:
                    HandleSensor(body);
                    WriteAscii(stream, "SENSOR OK\r\n");
                    break;
                case TypeTask:
                    HandleTask(body);
                    WriteAscii(stream, "TASK OK\r\n");
                    break;
                default:
                    WriteAscii(stream, "ERR type\r\n");
                    break;
            }
        }
    }

    /// <summary>UDP: magic "UAS1" | msgId u8 | len u16 BE | payload</summary>
    private static void HandleUdp(byte[] data)
    {
        if (data.Length < 7)
            return;
        if (data[0] != (byte)'U' || data[1] != (byte)'A' || data[2] != (byte)'S' || data[3] != (byte)'1')
            return;

        var msgId = data[4];
        var claimed = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(5, 2));
        var payload = data.AsSpan(7);

        if (claimed > 256)
            Environment.Exit(CrashExit);

        var slot = msgId switch
        {
            TelemNav => 48,
            TelemLink => 32,
            TelemBay => 64,
            _ => 24
        };

        if (payload.Length > slot || claimed > slot)
            Environment.Exit(CrashExit);

        CopyOverflow(payload, stackSize: slot, take: Math.Min(claimed, payload.Length));
    }

    private static bool TryReadPacket(NetworkStream stream, out byte type, out byte[] body)
    {
        type = 0;
        body = [];
        var hdr = new byte[3];
        if (!ReadExact(stream, hdr))
            return false;
        type = hdr[0];
        var rem = BinaryPrimitives.ReadUInt16BigEndian(hdr.AsSpan(1, 2));
        if (rem > 512)
            Environment.Exit(CrashExit);
        body = new byte[rem];
        return rem == 0 || ReadExact(stream, body);
    }

    private static void HandleHello(ReadOnlySpan<byte> body)
    {
        if (body.Length < 2)
            return;
        var nameLen = BinaryPrimitives.ReadUInt16BigEndian(body);
        var name = body.Length > 2 ? body[2..] : ReadOnlySpan<byte>.Empty;
        if (nameLen > 64 || name.Length > 64)
            Environment.Exit(CrashExit);
        CopyOverflow(name, stackSize: 64, take: Math.Min(nameLen, name.Length));
    }

    private static void HandleRoute(ReadOnlySpan<byte> body)
    {
        if (body.Length < 2)
            return;
        var count = BinaryPrimitives.ReadUInt16BigEndian(body);
        if (count > 16)
            Environment.Exit(CrashExit);
        const int wpSize = 12; // lat/lon/alt-shaped stub
        if (body.Length < 2 + count * wpSize)
            return;
        CopyOverflow(body[2..], stackSize: 16 * wpSize, take: Math.Min(count * wpSize, body.Length - 2));
    }

    private static void HandleSensor(ReadOnlySpan<byte> body)
    {
        // Sensor-bay config only — deliberately not a munitions / fire channel.
        if (body.Length < 2)
            return;
        var cfgLen = BinaryPrimitives.ReadUInt16BigEndian(body);
        var cfg = body.Length > 2 ? body[2..] : ReadOnlySpan<byte>.Empty;
        if (cfgLen > 128 || cfg.Length > 128)
            Environment.Exit(CrashExit);
        CopyOverflow(cfg, stackSize: 128, take: Math.Min(cfgLen, cfg.Length));
    }

    private static void HandleTask(ReadOnlySpan<byte> body)
    {
        if (body.Length < 3)
            return;
        var taskId = body[0];
        var argLen = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(1, 2));
        var args = body.Length > 3 ? body[3..] : ReadOnlySpan<byte>.Empty;
        _ = taskId;
        if (argLen > 96 || args.Length > 96)
            Environment.Exit(CrashExit);
        CopyOverflow(args, stackSize: 96, take: Math.Min(argLen, args.Length));
    }

    private static unsafe void CopyOverflow(ReadOnlySpan<byte> src, int stackSize, int take)
    {
        var buf = stackalloc byte[stackSize];
        var n = Math.Min(take, src.Length);
        for (var i = 0; i < n; i++)
            buf[i] = src[i];
    }

    private static bool ReadExact(NetworkStream stream, Span<byte> dest)
    {
        var off = 0;
        while (off < dest.Length)
        {
            int n;
            try { n = stream.Read(dest[off..]); }
            catch { return false; }
            if (n <= 0)
                return false;
            off += n;
        }
        return true;
    }

    private static void WriteAscii(NetworkStream stream, string s)
    {
        var bytes = Encoding.ASCII.GetBytes(s);
        stream.Write(bytes, 0, bytes.Length);
    }
}
