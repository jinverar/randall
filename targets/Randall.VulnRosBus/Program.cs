using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Randall.VulnRosBus;

/// <summary>
/// Intentionally vulnerable fictional robot bus (RRBS) — teaching target only.
/// Wire format resembles ROS-style topic/service/param messaging but is not ROS, DDS, or a real robot stack.
/// </summary>
internal static class Program
{
    private const ushort Magic = 0x5252; // 'RR'
    private const byte Version = 0x01;
    private const int MaxFrame = 2048;
    private const int MaxTopic = 48;
    private const int MaxPayload = 256;

    private static readonly byte[] TopicScratch = new byte[64];
    private static readonly byte[] PayloadScratch = new byte[280];
    private static readonly Dictionary<string, byte[]> Params = new(StringComparer.Ordinal);

    private static int _port = 15562;
    private static IPAddress _host = IPAddress.Loopback;

    private static int Main(string[] args)
    {
        for (var i = 0; i < args.Length; i++)
        {
            if ((args[i] is "-p" or "--port") && i + 1 < args.Length && int.TryParse(args[i + 1], out var p) && p is > 0 and < 65536)
            {
                _port = p;
                i++;
            }
            else if ((args[i] is "-h" or "--host" or "--bind" or "-b") && i + 1 < args.Length)
            {
                var h = args[++i];
                if (h is "0.0.0.0" or "*" or "any" or "all")
                    _host = IPAddress.Any;
                else if (!IPAddress.TryParse(h, out _host!))
                    _host = IPAddress.Loopback;
            }
        }

        Console.WriteLine($"randall-vulnrosbus: RRBS robot bus lab on {_host}:{_port} (TCP)");
        Console.WriteLine("randall-vulnrosbus: TOPIC / SERVICE / PARAM — teaching crashes only; not ROS/DDS.");

        var listener = new TcpListener(_host, _port);
        listener.Start();
        while (true)
        {
            using var client = listener.AcceptTcpClient();
            client.NoDelay = true;
            using var stream = client.GetStream();
            try
            {
                HandleClient(stream);
            }
            catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
            {
                // client disconnect
            }
        }
    }

    private static void HandleClient(NetworkStream stream)
    {
        var buf = new byte[MaxFrame];
        while (true)
        {
            // magic BE | ver | type | topicLen BE u16 | topic | payloadLen BE | payload
            if (!ReadExact(stream, buf.AsSpan(0, 6)))
                return;

            var magic = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(0, 2));
            var ver = buf[2];
            var type = buf[3];
            var topicLen = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(4, 2));

            if (magic != Magic || ver != Version)
            {
                WriteStatus(stream, 0x01);
                continue;
            }

            if (topicLen > MaxTopic)
                Environment.Exit(139);

            if (topicLen > 0)
            {
                if (!ReadExact(stream, TopicScratch.AsSpan(0, topicLen)))
                    return;
            }

            if (!ReadExact(stream, buf.AsSpan(0, 2)))
                return;
            var payloadLen = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(0, 2));

            if (payloadLen > MaxPayload)
                Environment.Exit(139);

            if (payloadLen > 0)
            {
                if (!ReadExact(stream, PayloadScratch.AsSpan(0, payloadLen)))
                    return;
            }

            switch (type)
            {
                case 0x01:
                    HandleTopic(topicLen, payloadLen);
                    WriteStatus(stream, 0x00);
                    break;
                case 0x02:
                    HandleService(topicLen, payloadLen);
                    WriteStatus(stream, 0x00);
                    break;
                case 0x03:
                    HandleParam(topicLen, payloadLen);
                    WriteStatus(stream, 0x00);
                    break;
                default:
                    WriteStatus(stream, 0x02);
                    break;
            }
        }
    }

    private static void HandleTopic(int topicLen, int payloadLen)
    {
        var name = Encoding.UTF8.GetString(TopicScratch, 0, topicLen);
        if (name.Contains("cmd_vel", StringComparison.OrdinalIgnoreCase) && payloadLen > 48)
            Environment.Exit(139);

        if (name.Length > 40 && payloadLen > 200)
            Environment.Exit(139);
    }

    private static void HandleService(int topicLen, int payloadLen)
    {
        var name = Encoding.UTF8.GetString(TopicScratch, 0, topicLen);
        if (name.StartsWith("/trigger", StringComparison.Ordinal) && payloadLen >= 4)
        {
            var reqId = BinaryPrimitives.ReadUInt32BigEndian(PayloadScratch.AsSpan(0, 4));
            if (reqId == 0xDEADBEEF)
                Environment.Exit(139);
        }

        if (payloadLen > MaxPayload - 8)
            Environment.Exit(139);
    }

    private static void HandleParam(int topicLen, int payloadLen)
    {
        var key = Encoding.UTF8.GetString(TopicScratch, 0, topicLen);
        if (string.IsNullOrEmpty(key))
            return;

        if (payloadLen == 0)
        {
            Params.Remove(key);
            return;
        }

        var copy = new byte[payloadLen];
        Buffer.BlockCopy(PayloadScratch, 0, copy, 0, payloadLen);
        Params[key] = copy;

        if (key.StartsWith("__internal__", StringComparison.Ordinal) && payloadLen > 128)
            Environment.Exit(139);
    }

    private static void WriteStatus(NetworkStream stream, byte code)
    {
        stream.WriteByte(code);
        stream.Flush();
    }

    private static bool ReadExact(NetworkStream stream, Span<byte> dest)
    {
        var offset = 0;
        while (offset < dest.Length)
        {
            var n = stream.Read(dest[offset..]);
            if (n <= 0)
                return false;
            offset += n;
        }
        return true;
    }
}
