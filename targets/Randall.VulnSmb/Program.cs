using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Randall.VulnSmb;

/// <summary>
/// Lab SMB2-shaped TCP server with NetBIOS session framing.
/// Not a real SMB stack — LAB USE ONLY (default :4455).
/// </summary>
internal static class Program
{
    private const ushort CmdNegotiate = 0;
    private const ushort CmdSessionSetup = 1;
    private const ushort CmdTreeConnect = 3;
    private const ushort CmdCreate = 5;
    private const ushort CmdRead = 8;
    private const ushort CmdWrite = 9;

    public static int Main(string[] args)
    {
        
        var port = 4455;
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


        Console.WriteLine($"Randall VulnSmb (NBSS+SMB2-shaped) TCP on {host}:{port} (use --host 0.0.0.0 to expose all interfaces)");
        Console.WriteLine("Lab only — Negotiate → SessionSetup → TreeConnect → Create/Write (Create overflows long names).");
        using var listener = new TcpListener(host, port);
        // Allow quick rebind after crash/restart (Windows exclusive bind → WSAEADDRINUSE 10048).
        listener.ExclusiveAddressUse = false;
        listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        try
        {
            listener.Start();
        }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.AddressAlreadyInUse)
        {
            Console.Error.WriteLine($"bind failed: address already in use ({host}:{port}) — {ex.Message}");
            return 10048;
        }

        while (true)
        {
            try
            {
                using var client = listener.AcceptTcpClient();
                HandleClient(client);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"accept/client: {ex.Message}");
            }
        }
    }

    private static void HandleClient(TcpClient client)
    {
        using var stream = client.GetStream();
        stream.ReadTimeout = 4000;
        stream.WriteTimeout = 4000;
        var buf = new byte[65536];

        while (true)
        {
            if (!TryReadNbss(stream, buf, out var payloadLen))
                return;

            var pdu = buf.AsSpan(0, payloadLen);
            if (pdu.Length < 16 || pdu[0] != 0xFE || pdu[1] != (byte)'S' || pdu[2] != (byte)'M' || pdu[3] != (byte)'B')
            {
                WriteAscii(stream, "BAD_SMB\r\n");
                continue;
            }

            var cmd = (ushort)(pdu[12] | (pdu[13] << 8));
            switch (cmd)
            {
                case CmdNegotiate:
                    WriteAscii(stream, "SMB_NEGO_OK\r\n");
                    break;
                case CmdSessionSetup:
                    WriteAscii(stream, "SMB_SESS_OK\r\n");
                    break;
                case CmdTreeConnect:
                    // IPC$ and share paths both OK in lab
                    WriteAscii(stream, "SMB_TREE_OK\r\n");
                    break;
                case CmdCreate:
                    // Pipe names (\pipe\…) or file paths — long bodies still crash
                    VulnHandlers.CrashableCreate(pdu);
                    WriteAscii(stream, "SMB_CREATE_OK\r\n");
                    break;
                case CmdRead:
                    WriteAscii(stream, "SMB_READ_OK\r\n");
                    break;
                case CmdWrite:
                    // Named-pipe → DCERPC reuse: DCE PDUs after SMB2 header
                    if (TryHandleDceOnWrite(pdu, stream))
                        break;
                    VulnHandlers.CrashableWrite(pdu);
                    WriteAscii(stream, "SMB_WRITE_OK\r\n");
                    break;
                default:
                    WriteAscii(stream, $"SMB_CMD_{cmd}\r\n");
                    break;
            }
        }
    }

    private static bool TryReadNbss(NetworkStream stream, byte[] buf, out int payloadLen)
    {
        payloadLen = 0;
        var hdr = new byte[4];
        var n = ReadExact(stream, hdr, 0, 4);
        if (n < 4)
            return false;

        // type 0x00 = session message; length is 24-bit big-endian
        payloadLen = (hdr[1] << 16) | (hdr[2] << 8) | hdr[3];
        if (payloadLen <= 0 || payloadLen > buf.Length)
        {
            WriteAscii(stream, "BAD_NBSS\r\n");
            return false;
        }

        return ReadExact(stream, buf, 0, payloadLen) == payloadLen;
    }

    private static int ReadExact(NetworkStream stream, byte[] buf, int offset, int count)
    {
        var got = 0;
        var idle = 0;
        while (got < count && idle < 50)
        {
            try
            {
                if (!stream.DataAvailable && got == 0)
                {
                    Thread.Sleep(20);
                    idle++;
                    continue;
                }

                var n = stream.Read(buf, offset + got, count - got);
                if (n <= 0)
                    break;
                got += n;
                idle = 0;
            }
            catch (IOException)
            {
                break;
            }
        }

        return got;
    }

    /// <summary>If Write body is DCE-shaped, reply like VulnRpc (BIND_ACK / RPC_OK).</summary>
    private static bool TryHandleDceOnWrite(ReadOnlySpan<byte> pdu, NetworkStream stream)
    {
        if (pdu.Length < 64 + 16)
            return false;
        var dce = pdu[64..];
        if (dce[0] != 0x05 || dce[1] != 0x00)
            return false;

        var ptype = dce[2];
        switch (ptype)
        {
            case 11: // bind
                WriteAscii(stream, "BIND_ACK\r\n");
                return true;
            case 0: // request
            {
                if (dce.Length >= 24)
                {
                    var opnum = (ushort)(dce[22] | (dce[23] << 8));
                    if (opnum == 2)
                        VulnHandlers.CrashableStub(dce.Length > 24 ? dce[24..] : ReadOnlySpan<byte>.Empty);
                }

                WriteAscii(stream, "RPC_OK\r\n");
                return true;
            }
            default:
                WriteAscii(stream, $"DCE_PTYPE_{ptype}\r\n");
                return true;
        }
    }

    private static void WriteAscii(NetworkStream stream, string s)
    {
        var bytes = Encoding.ASCII.GetBytes(s);
        stream.Write(bytes, 0, bytes.Length);
    }
}

internal static unsafe class VulnHandlers
{
    public static void CrashableCreate(ReadOnlySpan<byte> pdu)
    {
        // After 64-byte SMB2 header, treat rest as "name" region
        var name = pdu.Length > 64 ? pdu[64..] : ReadOnlySpan<byte>.Empty;
        const int stackSize = 96;
        // Lab scream: long Create names overflow the tiny buffer (managed runtimes
        // won't reliably SIGSEGV on stackalloc OOB — exit like other .NET lab targets).
        if (name.Length > stackSize)
            Environment.Exit(unchecked((int)0xC0000005));
        var buf = stackalloc byte[stackSize];
        for (var i = 0; i < name.Length; i++)
            buf[i] = name[i];
    }

    public static void CrashableWrite(ReadOnlySpan<byte> pdu)
    {
        var data = pdu.Length > 64 ? pdu[64..] : ReadOnlySpan<byte>.Empty;
        const int stackSize = 128;
        if (data.Length > stackSize)
            Environment.Exit(unchecked((int)0xC0000005));
        var buf = stackalloc byte[stackSize];
        for (var i = 0; i < data.Length; i++)
            buf[i] = data[i];
    }

    public static void CrashableStub(ReadOnlySpan<byte> stub)
    {
        const int stackSize = 64;
        if (stub.Length > stackSize)
            Environment.Exit(unchecked((int)0xC0000005));
        var buf = stackalloc byte[stackSize];
        for (var i = 0; i < stub.Length; i++)
            buf[i] = stub[i];
    }
}
