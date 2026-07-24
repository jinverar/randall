using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Randall.VulnRobotIo;

/// <summary>
/// Intentionally vulnerable fictional robot I/O bus (RMB1) — teaching target only.
/// Frame layout is Modbus-shaped for fuzz practice but is not Modbus/TCP or a fieldbus stack.
/// </summary>
internal static class Program
{
    private const ushort ProtocolId = 0x0001; // fictional — not Modbus 0
    private const int MaxAdu = 512;
    private const int CoilWords = 64;
    private const int RegWords = 128;

    private static readonly ushort[] Coils = new ushort[CoilWords];
    private static readonly ushort[] Holding = new ushort[RegWords];
    private static readonly byte[] PduScratch = new byte[300];

    private static int _port = 15502;
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

        Console.WriteLine($"randall-vulnrobotio: RMB1 robot I/O lab on {_host}:{_port} (TCP)");
        Console.WriteLine("randall-vulnrobotio: READ / WRITE / DIAG — teaching crashes only; not Modbus.");

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
                // disconnect
            }
        }
    }

    private static void HandleClient(NetworkStream stream)
    {
        var hdr = new byte[7];
        while (true)
        {
            if (!ReadExact(stream, hdr))
                return;

            var txId = BinaryPrimitives.ReadUInt16BigEndian(hdr.AsSpan(0, 2));
            var proto = BinaryPrimitives.ReadUInt16BigEndian(hdr.AsSpan(2, 2));
            var len = BinaryPrimitives.ReadUInt16BigEndian(hdr.AsSpan(4, 2));
            var unit = hdr[6];

            if (proto != ProtocolId)
            {
                WriteException(stream, txId, unit, 0x00, 0x01);
                continue;
            }

            if (len < 2 || len > MaxAdu)
                Environment.Exit(139);

            // len includes unit + remaining PDU; we already consumed unit
            var pduLen = len - 1;
            if (pduLen <= 0 || pduLen > PduScratch.Length)
                Environment.Exit(139);

            if (!ReadExact(stream, PduScratch.AsSpan(0, pduLen)))
                return;

            var func = PduScratch[0];
            switch (func)
            {
                case 0x01:
                    HandleReadCoils(stream, txId, unit, pduLen);
                    break;
                case 0x03:
                    HandleReadRegs(stream, txId, unit, pduLen);
                    break;
                case 0x05:
                    HandleWriteCoil(stream, txId, unit, pduLen);
                    break;
                case 0x06:
                    HandleWriteReg(stream, txId, unit, pduLen);
                    break;
                case 0x08:
                    HandleDiag(stream, txId, unit, pduLen);
                    break;
                default:
                    WriteException(stream, txId, unit, func, 0x01);
                    break;
            }
        }
    }

    private static void HandleReadCoils(NetworkStream stream, ushort txId, byte unit, int pduLen)
    {
        if (pduLen < 5)
        {
            WriteException(stream, txId, unit, 0x01, 0x03);
            return;
        }

        var addr = BinaryPrimitives.ReadUInt16BigEndian(PduScratch.AsSpan(1, 2));
        var qty = BinaryPrimitives.ReadUInt16BigEndian(PduScratch.AsSpan(3, 2));
        if (qty > 200)
            Environment.Exit(139);
        if (qty == 0 || addr + qty > CoilWords * 16)
        {
            WriteException(stream, txId, unit, 0x01, 0x02);
            return;
        }

        WriteEcho(stream, txId, unit, 0x01, PduScratch.AsSpan(0, 5));
    }

    private static void HandleReadRegs(NetworkStream stream, ushort txId, byte unit, int pduLen)
    {
        if (pduLen < 5)
        {
            WriteException(stream, txId, unit, 0x03, 0x03);
            return;
        }

        var addr = BinaryPrimitives.ReadUInt16BigEndian(PduScratch.AsSpan(1, 2));
        var qty = BinaryPrimitives.ReadUInt16BigEndian(PduScratch.AsSpan(3, 2));
        if (qty > 64)
            Environment.Exit(139);
        if (qty == 0 || addr + qty > RegWords)
        {
            WriteException(stream, txId, unit, 0x03, 0x02);
            return;
        }

        WriteEcho(stream, txId, unit, 0x03, PduScratch.AsSpan(0, 5));
    }

    private static void HandleWriteCoil(NetworkStream stream, ushort txId, byte unit, int pduLen)
    {
        if (pduLen < 5)
        {
            WriteException(stream, txId, unit, 0x05, 0x03);
            return;
        }

        var addr = BinaryPrimitives.ReadUInt16BigEndian(PduScratch.AsSpan(1, 2));
        var value = BinaryPrimitives.ReadUInt16BigEndian(PduScratch.AsSpan(3, 2));
        if (addr >= CoilWords * 16)
            Environment.Exit(139);

        Coils[addr / 16] = value;
        WriteEcho(stream, txId, unit, 0x05, PduScratch.AsSpan(0, 5));
    }

    private static void HandleWriteReg(NetworkStream stream, ushort txId, byte unit, int pduLen)
    {
        if (pduLen < 5)
        {
            WriteException(stream, txId, unit, 0x06, 0x03);
            return;
        }

        var addr = BinaryPrimitives.ReadUInt16BigEndian(PduScratch.AsSpan(1, 2));
        var value = BinaryPrimitives.ReadUInt16BigEndian(PduScratch.AsSpan(3, 2));
        if (addr >= RegWords)
            Environment.Exit(139);

        Holding[addr] = value;
        if (addr == 0x7F && value == 0xBEEF)
            Environment.Exit(139);

        WriteEcho(stream, txId, unit, 0x06, PduScratch.AsSpan(0, 5));
    }

    private static void HandleDiag(NetworkStream stream, ushort txId, byte unit, int pduLen)
    {
        if (pduLen < 3)
        {
            WriteException(stream, txId, unit, 0x08, 0x03);
            return;
        }

        var sub = BinaryPrimitives.ReadUInt16BigEndian(PduScratch.AsSpan(1, 2));
        if (sub == 0xFFFF || pduLen > 64)
            Environment.Exit(139);

        WriteEcho(stream, txId, unit, 0x08, PduScratch.AsSpan(0, Math.Min(pduLen, 5)));
    }

    private static void WriteEcho(NetworkStream stream, ushort txId, byte unit, byte func, ReadOnlySpan<byte> pduPrefix)
    {
        // Minimal ACK: header + unit + func + first few PDU bytes
        var bodyLen = 1 + 1 + pduPrefix.Length; // unit already in MBAP len sense — simplify
        Span<byte> outBuf = stackalloc byte[8 + pduPrefix.Length];
        BinaryPrimitives.WriteUInt16BigEndian(outBuf, txId);
        BinaryPrimitives.WriteUInt16BigEndian(outBuf[2..], ProtocolId);
        BinaryPrimitives.WriteUInt16BigEndian(outBuf[4..], (ushort)(1 + 1 + pduPrefix.Length));
        outBuf[6] = unit;
        outBuf[7] = func;
        pduPrefix.CopyTo(outBuf[8..]);
        stream.Write(outBuf[..(8 + pduPrefix.Length)]);
        stream.Flush();
        _ = bodyLen;
    }

    private static void WriteException(NetworkStream stream, ushort txId, byte unit, byte func, byte code)
    {
        Span<byte> outBuf = stackalloc byte[9];
        BinaryPrimitives.WriteUInt16BigEndian(outBuf, txId);
        BinaryPrimitives.WriteUInt16BigEndian(outBuf[2..], ProtocolId);
        BinaryPrimitives.WriteUInt16BigEndian(outBuf[4..], 3);
        outBuf[6] = unit;
        outBuf[7] = (byte)(func | 0x80);
        outBuf[8] = code;
        stream.Write(outBuf);
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
