using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Randall.VulnDrone;

/// <summary>
/// Fictional RDL1 drone / GCS lab target (not MAVLink / not a real autopilot).
/// UDP telemetry + TCP command/mission parsers with intentional length bugs.
/// LAB USE ONLY — loopback by default; no RF, arming, or vehicle control.
/// </summary>
internal static class Program
{
    private const int CrashExit = unchecked((int)0xC0000005);

    public static int Main(string[] args)
    {
        var port = 15550;
        var host = IPAddress.Loopback;
        var mode = "udp";

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

        if (mode is "tcp" or "gcs")
        {
            if (port == 15550)
                port = 15551;
            RunTcp(host, port);
        }
        else
        {
            RunUdp(host, port);
        }

        return 0;
    }

    private static void RunUdp(IPAddress host, int port)
    {
        Console.WriteLine($"Randall VulnDrone RDL1 UDP telemetry on {host}:{port} (lab only; --host 0.0.0.0 to expose)");
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
                Console.Error.WriteLine($"udp recv: {ex.Message}");
            }
        }
    }

    private static void RunTcp(IPAddress host, int port)
    {
        Console.WriteLine($"Randall VulnDrone RDL1 TCP GCS link on {host}:{port} (lab only; --host 0.0.0.0 to expose)");
        using var listener = new TcpListener(host, port);
        listener.Start();

        while (true)
        {
            try
            {
                using var client = listener.AcceptTcpClient();
                using var stream = client.GetStream();
                stream.ReadTimeout = 5000;
                WriteAscii(stream, "RDL1 GCS READY\r\n");

                var buf = new byte[65536];
                int n;
                try { n = stream.Read(buf, 0, buf.Length); }
                catch { continue; }
                if (n <= 0)
                    continue;

                var reply = HandleTcp(buf.AsSpan(0, n));
                if (reply is not null)
                    WriteAscii(stream, reply);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"tcp: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// UDP frame: magic "RDL1" | msgId u8 | len u16 LE | payload[len]
    /// Crashes: claimed len &gt; 256, or msgId 0xFF with oversized body.
    /// </summary>
    private static void HandleUdp(byte[] data)
    {
        if (data.Length < 7)
            return;
        if (data[0] != (byte)'R' || data[1] != (byte)'D' || data[2] != (byte)'L' || data[3] != (byte)'1')
            return;

        var msgId = data[4];
        var claimed = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(5, 2));
        var payload = data.AsSpan(7);

        // Length-field lie → classic lab crash
        if (claimed > 256)
            Environment.Exit(CrashExit);

        // "debug dump" path: msg-id 0xFF copies claimed bytes into a tiny stack buffer
        if (msgId == 0xFF)
        {
            CopyOverflow(payload, stackSize: 64, take: Math.Min(claimed, payload.Length));
            return;
        }

        // Heartbeat / attitude / GPS — copy into fixed telemetry slot (overflow if body longer than slot)
        var slot = msgId switch
        {
            1 => 48,   // HEARTBEAT
            2 => 64,   // ATTITUDE
            3 => 96,   // GPS
            _ => 32
        };

        if (payload.Length > slot)
            Environment.Exit(CrashExit);

        CopyOverflow(payload, stackSize: slot, take: Math.Min((int)claimed, payload.Length));
    }

    /// <summary>
    /// TCP frames after optional banner:
    ///   RDL1 H &lt;name\0&gt;          — HELLO (name &gt; 64 → crash)
    ///   RDL1 C &lt;cmd u8&gt;&lt;len u16&gt;&lt;args&gt; — CMD (len &gt; 128 → crash)
    ///   RDL1 M &lt;count u16&gt;&lt;waypoints…&gt; — MISSION (count &gt; 16 → crash)
    /// </summary>
    private static string? HandleTcp(ReadOnlySpan<byte> raw)
    {
        if (raw.Length < 5)
            return "ERR short\r\n";
        if (raw[0] != (byte)'R' || raw[1] != (byte)'D' || raw[2] != (byte)'L' || raw[3] != (byte)'1')
            return "ERR magic\r\n";

        var kind = (char)raw[4];
        var body = raw[5..];

        switch (kind)
        {
            case 'H':
            case 'h':
                return HandleHello(body);
            case 'C':
            case 'c':
                return HandleCmd(body);
            case 'M':
            case 'm':
                return HandleMission(body);
            default:
                return "ERR type\r\n";
        }
    }

    private static string HandleHello(ReadOnlySpan<byte> body)
    {
        var z = body.IndexOf((byte)0);
        var name = z >= 0 ? body[..z] : body;
        if (name.Length > 64)
            Environment.Exit(CrashExit);
        CopyOverflow(name, stackSize: 64, take: name.Length);
        return "HELLO OK\r\n";
    }

    private static string HandleCmd(ReadOnlySpan<byte> body)
    {
        if (body.Length < 3)
            return "ERR cmd\r\n";
        var cmd = body[0];
        var len = BinaryPrimitives.ReadUInt16LittleEndian(body[1..3]);
        if (len > 128)
            Environment.Exit(CrashExit);
        var args = body.Length > 3 ? body[3..] : ReadOnlySpan<byte>.Empty;
        CopyOverflow(args, stackSize: 128, take: Math.Min(len, args.Length));
        return cmd == 0x2A ? "CMD DEBUG\r\n" : "CMD OK\r\n";
    }

    private static string HandleMission(ReadOnlySpan<byte> body)
    {
        if (body.Length < 2)
            return "ERR mission\r\n";
        var count = BinaryPrimitives.ReadUInt16LittleEndian(body);
        // Lab crash: too many waypoints for the fixed mission table
        if (count > 16)
            Environment.Exit(CrashExit);

        const int wpSize = 8; // lat+lon floats
        var need = 2 + count * wpSize;
        if (body.Length < need)
            return "ERR trunc\r\n";

        // Fixed table of 16 waypoints; overflow if we copy past table using body length lie
        CopyOverflow(body[2..], stackSize: 16 * wpSize, take: Math.Min(count * wpSize, body.Length - 2));
        return "MISSION OK\r\n";
    }

    private static unsafe void CopyOverflow(ReadOnlySpan<byte> src, int stackSize, int take)
    {
        var buf = stackalloc byte[stackSize];
        var n = Math.Min(take, src.Length);
        // Intentional lab bug: write past stackSize when caller lies about length
        for (var i = 0; i < n; i++)
        {
            if (i >= stackSize)
                Environment.Exit(CrashExit);
            buf[i] = src[i];
        }
    }

    private static void WriteAscii(NetworkStream stream, string s)
    {
        var bytes = Encoding.ASCII.GetBytes(s);
        stream.Write(bytes, 0, bytes.Length);
    }
}
