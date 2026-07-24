using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Randall.VulnTurret;

/// <summary>
/// Fictional STT1 sentry-station lab (pan/tilt/track parsers with intentional length bugs).
/// NOT a weapon system — no fire control, arming, munitions, IFF, or real turret hardware.
/// LAB USE ONLY — loopback by default.
/// </summary>
internal static class Program
{
    private const int CrashExit = 139;

    private const byte TypeHello = 0x01;
    private const byte TypeSlew = 0x02;
    private const byte TypeTrack = 0x03;
    private const byte TypeConfig = 0x04;

    private const byte TelemPose = 0x10;
    private const byte TelemTrack = 0x11;
    private const byte TelemHealth = 0x1F;

    public static int Main(string[] args)
    {
        var port = 15660;
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
            if (port == 15660)
                port = 15661;
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
        Console.WriteLine($"Randall VulnTurret STT1 sentry TCP on {host}:{port} (lab only; not a weapon system)");
        using var listener = new TcpListener(host, port);
        listener.Start();

        while (true)
        {
            try
            {
                using var client = listener.AcceptTcpClient();
                using var stream = client.GetStream();
                stream.ReadTimeout = 5000;
                WriteAscii(stream, "STT1 SENTRY READY\r\n");
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
        Console.WriteLine($"Randall VulnTurret STT1 telemetry UDP on {host}:{port} (lab only; not a weapon system)");
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
                case TypeSlew:
                    HandleSlew(body);
                    WriteAscii(stream, "SLEW OK\r\n");
                    break;
                case TypeTrack:
                    HandleTrack(body);
                    WriteAscii(stream, "TRACK OK\r\n");
                    break;
                case TypeConfig:
                    HandleConfig(body);
                    WriteAscii(stream, "CONFIG OK\r\n");
                    break;
                default:
                    WriteAscii(stream, "ERR type\r\n");
                    break;
            }
        }
    }

    /// <summary>UDP: magic "STT1" | msgId u8 | len u16 BE | payload</summary>
    private static void HandleUdp(byte[] data)
    {
        if (data.Length < 7)
            return;
        if (data[0] != (byte)'S' || data[1] != (byte)'T' || data[2] != (byte)'T' || data[3] != (byte)'1')
            return;

        var msgId = data[4];
        var claimed = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(5, 2));
        var payload = data.AsSpan(7);

        if (claimed > 256)
            Environment.Exit(CrashExit);

        var slot = msgId switch
        {
            TelemPose => 32,
            TelemTrack => 96,
            TelemHealth => 24,
            _ => 16
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

    private static void HandleSlew(ReadOnlySpan<byte> body)
    {
        if (body.Length < 2)
            return;
        // count of az/el float pairs (8 bytes each)
        var count = BinaryPrimitives.ReadUInt16BigEndian(body);
        if (count > 8)
            Environment.Exit(CrashExit);
        const int pairSize = 8;
        if (body.Length < 2 + count * pairSize)
            return;
        CopyOverflow(body[2..], stackSize: 8 * pairSize, take: Math.Min(count * pairSize, body.Length - 2));
    }

    private static void HandleTrack(ReadOnlySpan<byte> body)
    {
        if (body.Length < 4)
            return;
        var trackId = BinaryPrimitives.ReadUInt16BigEndian(body);
        var blobLen = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(2, 2));
        var blob = body.Length > 4 ? body[4..] : ReadOnlySpan<byte>.Empty;
        _ = trackId;
        if (blobLen > 128 || blob.Length > 128)
            Environment.Exit(CrashExit);
        CopyOverflow(blob, stackSize: 128, take: Math.Min(blobLen, blob.Length));
    }

    private static void HandleConfig(ReadOnlySpan<byte> body)
    {
        if (body.Length < 2)
            return;
        var keyLen = BinaryPrimitives.ReadUInt16BigEndian(body);
        if (body.Length < 2 + keyLen + 2)
            return;
        var key = body.Slice(2, keyLen);
        var valLen = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(2 + keyLen, 2));
        var val = body.Length > 4 + keyLen ? body[(4 + keyLen)..] : ReadOnlySpan<byte>.Empty;
        var keyStr = Encoding.UTF8.GetString(key);
        if (keyStr.StartsWith("__internal__", StringComparison.Ordinal) && valLen > 64)
            Environment.Exit(CrashExit);
        if (valLen > 96 || val.Length > 96)
            Environment.Exit(CrashExit);
        CopyOverflow(val, stackSize: 96, take: Math.Min(valLen, val.Length));
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
