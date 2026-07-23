using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Randall.VulnRobot;

/// <summary>
/// Fictional RBT1 robot-arm / motion-controller lab (not ROS, UR, Fanuc, ABB, or any real robot stack).
/// HELLO / JOINT / TRAJ / TOOL parsers with intentional length bugs.
/// LAB USE ONLY — loopback by default; no motors, pendant, safety PLC, or fieldbus.
/// </summary>
internal static class Program
{
    /// <summary>Shell-style SIGSEGV status (128+11) for triage / IsCrashExitCode.</summary>
    private const int CrashExit = 139;

    private const byte TypeHello = 0x01;
    private const byte TypeJoint = 0x02;
    private const byte TypeTraj = 0x03;
    private const byte TypeTool = 0x04;

    public static int Main(string[] args)
    {
        var port = 15560;
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

        Console.WriteLine($"Randall VulnRobot RBT1 motion lab on {host}:{port} (lab only; --host 0.0.0.0 to expose)");
        using var listener = new TcpListener(host, port);
        listener.Start();

        while (true)
        {
            try
            {
                using var client = listener.AcceptTcpClient();
                using var stream = client.GetStream();
                stream.ReadTimeout = 5000;
                WriteAscii(stream, "RBT1 ROBOT READY\r\n");
                HandleSession(stream);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"tcp: {ex.Message}");
            }
        }
    }

    private static void HandleSession(NetworkStream stream)
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
                case TypeJoint:
                    HandleJoint(body);
                    WriteAscii(stream, "JOINT OK\r\n");
                    break;
                case TypeTraj:
                    HandleTraj(body);
                    WriteAscii(stream, "TRAJ OK\r\n");
                    break;
                case TypeTool:
                    HandleTool(body);
                    WriteAscii(stream, "TOOL OK\r\n");
                    break;
                default:
                    WriteAscii(stream, "ERR type\r\n");
                    break;
            }
        }
    }

    /// <summary>Frame: type_u8 | rem_len_u16_BE | body[rem_len]</summary>
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

    /// <summary>HELLO: name_len u16 BE + name — crash when name_len &gt; 64 or name bytes &gt; 64</summary>
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

    /// <summary>JOINT: joint_count u16 BE + angles (4 bytes each) — crash when count &gt; 8</summary>
    private static void HandleJoint(ReadOnlySpan<byte> body)
    {
        if (body.Length < 2)
            return;
        var count = BinaryPrimitives.ReadUInt16BigEndian(body);
        if (count > 8)
            Environment.Exit(CrashExit);
        const int angleSize = 4;
        var need = 2 + count * angleSize;
        if (body.Length < need)
            return;
        CopyOverflow(body[2..], stackSize: 8 * angleSize, take: Math.Min(count * angleSize, body.Length - 2));
    }

    /// <summary>TRAJ: waypoint_count u16 BE + waypoints (8 bytes) — crash when count &gt; 16</summary>
    private static void HandleTraj(ReadOnlySpan<byte> body)
    {
        if (body.Length < 2)
            return;
        var count = BinaryPrimitives.ReadUInt16BigEndian(body);
        if (count > 16)
            Environment.Exit(CrashExit);
        const int wpSize = 8;
        var need = 2 + count * wpSize;
        if (body.Length < need)
            return;
        CopyOverflow(body[2..], stackSize: 16 * wpSize, take: Math.Min(count * wpSize, body.Length - 2));
    }

    /// <summary>TOOL: path_len u16 BE + path bytes — crash when path_len &gt; 128 or path &gt; 128</summary>
    private static void HandleTool(ReadOnlySpan<byte> body)
    {
        if (body.Length < 2)
            return;
        var pathLen = BinaryPrimitives.ReadUInt16BigEndian(body);
        var path = body.Length > 2 ? body[2..] : ReadOnlySpan<byte>.Empty;
        if (pathLen > 128 || path.Length > 128)
            Environment.Exit(CrashExit);
        CopyOverflow(path, stackSize: 128, take: Math.Min(pathLen, path.Length));
    }

    private static unsafe void CopyOverflow(ReadOnlySpan<byte> src, int stackSize, int take)
    {
        var buf = stackalloc byte[stackSize];
        var n = Math.Min(take, src.Length);
        for (var i = 0; i < n; i++)
            buf[i] = src[i];
    }

    private static void WriteAscii(NetworkStream stream, string s)
    {
        var bytes = Encoding.ASCII.GetBytes(s);
        stream.Write(bytes, 0, bytes.Length);
    }

    private static void WriteBytes(NetworkStream stream, ReadOnlySpan<byte> bytes) =>
        stream.Write(bytes);
}
