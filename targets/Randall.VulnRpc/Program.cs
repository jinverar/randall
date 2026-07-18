using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Randall.VulnRpc;

/// <summary>
/// Minimal DCE/RPC-shaped lab TCP server — bind + request framing, crashable opnum.
/// LAB USE ONLY. Not a Windows RPC / NDR implementation.
/// </summary>
internal static class Program
{
    private const byte PtypeRequest = 0;
    private const byte PtypeBind = 11;
    private const byte PtypeBindAck = 12;

    public static int Main(string[] args)
    {
        
        var port = 1355;
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


        Console.WriteLine($"Randall VulnRpc (DCE-shaped) TCP on {host}:{port} (use --host 0.0.0.0 to expose all interfaces)");
        Console.WriteLine("Lab only — bind (ptype 11) → request (ptype 0). Opnum 2 overflows stub.");
        using var listener = new TcpListener(host, port);
        listener.Start();

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
        stream.ReadTimeout = 3000;
        stream.WriteTimeout = 3000;
        var buf = new byte[65536];

        while (true)
        {
            var n = ReadAtLeast(stream, buf, 16);
            if (n < 16)
                return;

            var fragLen = buf[8] | (buf[9] << 8);
            if (fragLen < 16 || fragLen > buf.Length)
            {
                WriteAscii(stream, "BAD_FRAG\r\n");
                return;
            }

            while (n < fragLen)
            {
                var got = stream.Read(buf, n, fragLen - n);
                if (got <= 0)
                    return;
                n += got;
            }

            var ptype = buf[2];
            switch (ptype)
            {
                case PtypeBind:
                    WriteAscii(stream, "BIND_ACK\r\n");
                    break;
                case PtypeRequest:
                    HandleRequest(buf.AsSpan(0, fragLen), stream);
                    break;
                case PtypeBindAck:
                    WriteAscii(stream, "OK\r\n");
                    break;
                default:
                    WriteAscii(stream, $"UNK_PTYPE_{ptype}\r\n");
                    break;
            }
        }
    }

    private static void HandleRequest(ReadOnlySpan<byte> pdu, NetworkStream stream)
    {
        // common header 16 + alloc_hint 4 + p_cont_id 2 + opnum 2 + stub
        if (pdu.Length < 24)
        {
            WriteAscii(stream, "SHORT\r\n");
            return;
        }

        var opnum = (ushort)(pdu[22] | (pdu[23] << 8));
        var stub = pdu[24..];

        switch (opnum)
        {
            case 1:
                WriteAscii(stream, "RPC_OK\r\n");
                break;
            case 2:
                // Intentional stack smash on long stub — lab crash signal
                VulnHandlers.CrashableStub(stub);
                WriteAscii(stream, "RPC_OK\r\n");
                break;
            default:
                WriteAscii(stream, $"OP_{opnum}\r\n");
                break;
        }
    }

    private static int ReadAtLeast(NetworkStream stream, byte[] buf, int min)
    {
        var n = 0;
        var idle = 0;
        while (n < min && idle < 40)
        {
            try
            {
                if (!stream.DataAvailable && n == 0)
                {
                    Thread.Sleep(25);
                    idle++;
                    continue;
                }

                var got = stream.Read(buf, n, buf.Length - n);
                if (got <= 0)
                    break;
                n += got;
                idle = 0;
            }
            catch (IOException)
            {
                break;
            }
        }

        return n;
    }

    private static void WriteAscii(NetworkStream stream, string s)
    {
        var bytes = Encoding.ASCII.GetBytes(s);
        stream.Write(bytes, 0, bytes.Length);
    }
}

internal static unsafe class VulnHandlers
{
    public static void CrashableStub(ReadOnlySpan<byte> stub)
    {
        const int stackSize = 64;
        var buf = stackalloc byte[stackSize];
        for (var i = 0; i < stub.Length; i++)
            buf[i] = stub[i];
    }
}
