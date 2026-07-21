using System.Net.Sockets;

namespace Randall.Infrastructure;

/// <summary>
/// Shared TCP/UDP listen readiness probes — used by Target Runtime, post-start wait-port,
/// and coverage-TCP DynamoRIO respawn (which needs longer than a fixed sleep).
/// </summary>
public static class PortReadiness
{
    /// <summary>Poll until <paramref name="host"/>:<paramref name="port"/> accepts, or timeout.</summary>
    public static async Task<bool> WaitAsync(
        string host,
        int port,
        string protocol,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        if (port <= 0)
            return false;

        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Probe(host, port, protocol))
                return true;
            await Task.Delay(150, cancellationToken);
        }

        return false;
    }

    /// <summary>True when nothing accepts on host:port (safe to bind a new listener).</summary>
    public static Task<bool> WaitUntilFreeAsync(
        string host,
        int port,
        string protocol,
        TimeSpan timeout,
        CancellationToken cancellationToken = default) =>
        Task.Run(
            () => ProcessTreeKill.WaitUntilPortFree(host, port, protocol, timeout, killListeners: false),
            cancellationToken);

    public static bool Probe(string host, int port, string protocol)
    {
        try
        {
            if (protocol.Equals("udp", StringComparison.OrdinalIgnoreCase))
            {
                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = 400;
                udp.Connect(host, port);
                udp.Send([0x00, 0x01], 2);
                return true;
            }

            using var tcp = new TcpClient();
            var task = tcp.ConnectAsync(host, port);
            return task.Wait(800) && tcp.Connected;
        }
        catch
        {
            return false;
        }
    }
}
