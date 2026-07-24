using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Randall.VulnMqtt;

/// <summary>
/// Fictional MQTT-shaped IoT broker lab (RMQ1 framing — not wire-compatible with real MQTT brokers).
/// CONNECT / PUBLISH / SUBSCRIBE parsers with intentional length bugs.
/// LAB USE ONLY — loopback by default; no broker federation, no auth crypto, no device control.
/// </summary>
internal static class Program
{
    /// <summary>Shell-style SIGSEGV status (128+11) so triage / IsCrashExitCode treat it as a scream.</summary>
    private const int CrashExit = 139;

    // MQTT-ish type nibbles in the high 4 bits (lab uses fixed u16 remaining length, not MQTT varint).
    private const byte TypeConnect = 0x10;
    private const byte TypePublish = 0x30;
    private const byte TypeSubscribe = 0x80; // wire often 0x82 (flags); match on high nibble

    public static int Main(string[] args)
    {
        var port = 18883;
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

        Console.WriteLine($"Randall VulnMqtt RMQ1 IoT lab on {host}:{port} (lab only; --host 0.0.0.0 to expose)");
        using var listener = new TcpListener(host, port);
        listener.Start();

        while (true)
        {
            try
            {
                using var client = listener.AcceptTcpClient();
                using var stream = client.GetStream();
                stream.ReadTimeout = 5000;
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

            switch (type & 0xF0)
            {
                case TypeConnect:
                    HandleConnect(body);
                    WriteBytes(stream, [0x20, 0x00, 0x02, 0x00, 0x00]); // CONNACK-shaped
                    break;
                case TypePublish:
                    HandlePublish(body);
                    WriteBytes(stream, [0x40, 0x00, 0x02, 0x00, 0x01]); // PUBACK-shaped
                    break;
                case TypeSubscribe:
                    HandleSubscribe(body);
                    WriteBytes(stream, [0x90, 0x00, 0x03, 0x00, 0x01, 0x00]); // SUBACK-shaped
                    break;
                default:
                    WriteBytes(stream, [0x00, 0x00, 0x00]);
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

    /// <summary>
    /// CONNECT body: proto_len u16 BE + proto + level u8 + flags u8 + keepalive u16 BE + client_id_len u16 BE + client_id
    /// Crash: client_id_len &gt; 64 or id bytes &gt; 64
    /// </summary>
    private static void HandleConnect(ReadOnlySpan<byte> body)
    {
        if (body.Length < 2)
            return;
        var protoLen = BinaryPrimitives.ReadUInt16BigEndian(body);
        if (body.Length < 2 + protoLen + 2 + 2 + 2)
            return;
        var o = 2 + protoLen + 2 + 2; // skip proto + level/flags + keepalive
        if (body.Length < o + 2)
            return;
        var idLen = BinaryPrimitives.ReadUInt16BigEndian(body[o..]);
        o += 2;
        var id = body.Length > o ? body[o..] : ReadOnlySpan<byte>.Empty;
        if (idLen > 64 || id.Length > 64)
            Environment.Exit(CrashExit);
        CopyOverflow(id, stackSize: 64, take: Math.Min(idLen, id.Length));
    }

    /// <summary>
    /// PUBLISH body: topic_len u16 BE + topic + payload
    /// Crash: topic_len &gt; 128, topic bytes &gt; 128, or payload &gt; 256
    /// </summary>
    private static void HandlePublish(ReadOnlySpan<byte> body)
    {
        if (body.Length < 2)
            return;
        var topicLen = BinaryPrimitives.ReadUInt16BigEndian(body);
        var avail = Math.Max(0, body.Length - 2);
        if (topicLen > 128 || avail > 128)
            Environment.Exit(CrashExit);
        var takeTopic = Math.Min((int)topicLen, avail);
        var topic = body.Slice(2, takeTopic);
        CopyOverflow(topic, stackSize: 128, take: topic.Length);

        var payload = body.Length > 2 + takeTopic ? body[(2 + takeTopic)..] : ReadOnlySpan<byte>.Empty;
        if (payload.Length > 256)
            Environment.Exit(CrashExit);
        CopyOverflow(payload, stackSize: 256, take: payload.Length);
    }

    /// <summary>
    /// SUBSCRIBE body: pkt_id u16 BE + count u16 BE + (topic_len u16 BE + topic + qos u8)*count
    /// Crash: count &gt; 8 or any topic_len &gt; 96
    /// </summary>
    private static void HandleSubscribe(ReadOnlySpan<byte> body)
    {
        if (body.Length < 4)
            return;
        var count = BinaryPrimitives.ReadUInt16BigEndian(body[2..]);
        if (count > 8)
            Environment.Exit(CrashExit);

        var o = 4;
        for (var i = 0; i < count; i++)
        {
            if (body.Length < o + 2)
                return;
            var tlen = BinaryPrimitives.ReadUInt16BigEndian(body[o..]);
            if (tlen > 96)
                Environment.Exit(CrashExit);
            o += 2;
            if (body.Length < o + tlen + 1)
                return;
            var topic = body.Slice(o, tlen);
            CopyOverflow(topic, stackSize: 96, take: topic.Length);
            o += tlen + 1;
        }
    }

    private static unsafe void CopyOverflow(ReadOnlySpan<byte> src, int stackSize, int take)
    {
        var buf = stackalloc byte[stackSize];
        var n = Math.Min(take, src.Length);
        // VulnTftp-style: write past the fixed slot when take exceeds stackSize.
        for (var i = 0; i < n; i++)
            buf[i] = src[i];
    }

    private static void WriteBytes(NetworkStream stream, ReadOnlySpan<byte> bytes) =>
        stream.Write(bytes);
}
