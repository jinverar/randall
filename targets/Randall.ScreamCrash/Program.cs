using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

// Lab-only target: TCP echo that ACCESS_VIOLATIONs on a magic token.
// Used to regression-test Randfuzz Scream (debug-attach → dump).

var port = 19999;
for (var i = 0; i < args.Length; i++)
{
    if (args[i] is "-p" or "--port" && i + 1 < args.Length && int.TryParse(args[i + 1], out var p))
        port = p;
}

Console.WriteLine($"randall-screamcrash listening on 127.0.0.1:{port}");
Console.WriteLine("Send a line containing SCREAM to trigger ACCESS_VIOLATION.");

var listener = new TcpListener(IPAddress.Loopback, port);
listener.Start();

while (true)
{
    using var client = await listener.AcceptTcpClientAsync();
    await using var stream = client.GetStream();
    var banner = Encoding.ASCII.GetBytes("SCREAMCRASH ready\r\n");
    await stream.WriteAsync(banner);

    var buf = new byte[4096];
    var n = await stream.ReadAsync(buf);
    if (n <= 0)
        continue;

    var text = Encoding.ASCII.GetString(buf, 0, n);
    Console.WriteLine($"recv ({n}): {text.Trim()}");

    if (text.Contains("SCREAM", StringComparison.OrdinalIgnoreCase))
    {
        Console.WriteLine("Triggering ACCESS_VIOLATION…");
        Console.Out.Flush();
        CrashAv.Trigger();
    }

    var ok = Encoding.ASCII.GetBytes("OK\r\n");
    await stream.WriteAsync(ok);
}

internal static class CrashAv
{
    // Native helper (targets/Randall.ScreamCrash/native/scream_av.c) — real SEH AV.
    [DllImport("scream_av", CallingConvention = CallingConvention.Cdecl, EntryPoint = "crash_av")]
    private static extern void NativeCrashAv();

    public static void Trigger()
    {
        try
        {
            NativeCrashAv();
        }
        catch (DllNotFoundException)
        {
            // Fallback if native helper missing — may surface as CLR exception.
            RaiseException(0xC0000005, 0, 0, IntPtr.Zero);
        }
    }

    [DllImport("kernel32.dll")]
    private static extern void RaiseException(uint dwExceptionCode, uint dwExceptionFlags, uint nNumberOfArguments, IntPtr lpArguments);
}
