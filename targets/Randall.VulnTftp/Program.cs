using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Randall.VulnTftp;

/// <summary>Minimal TFTP lab server — RRQ/WRQ filename overflows. LAB USE ONLY.</summary>
internal static class Program
{
    public static int Main(string[] args)
    {
        var port = 6969;
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i] is "-p" or "--port" && int.TryParse(args[i + 1], out var p))
                port = p;
        }

        Console.WriteLine($"Randall VulnTftp UDP on 0.0.0.0:{port}");
        using var client = new UdpClient(port);

        while (true)
        {
            try
            {
                var remote = new IPEndPoint(IPAddress.Any, 0);
                var data = client.Receive(ref remote);
                if (data.Length >= 2)
                    HandleDatagram(data);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"recv: {ex.Message}");
            }
        }
    }

    private static void HandleDatagram(byte[] data)
    {
        var opcode = (ushort)(data[0] << 8 | data[1]);
        var payload = data.AsSpan(2);
        switch (opcode)
        {
            case 1: // RRQ
                VulnHandlers.ReadRequest(payload);
                break;
            case 2: // WRQ
                VulnHandlers.WriteRequest(payload);
                break;
            default:
                break;
        }
    }
}

internal static unsafe class VulnHandlers
{
    public static void ReadRequest(ReadOnlySpan<byte> data) =>
        CopyFilename(data, stackSize: 128);

    public static void WriteRequest(ReadOnlySpan<byte> data) =>
        CopyFilename(data, stackSize: 160);

    private static void CopyFilename(ReadOnlySpan<byte> src, int stackSize)
    {
        var buf = stackalloc byte[stackSize];
        for (var i = 0; i < src.Length; i++)
            buf[i] = src[i];
    }
}
