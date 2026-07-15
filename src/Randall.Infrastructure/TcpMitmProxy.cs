using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Randall.Contracts;

namespace Randall.Infrastructure;

public sealed record CapturedMessage(
    Guid Id,
    string Direction,
    DateTimeOffset At,
    byte[] Data,
    string? CommandTag);

/// <summary>Leg 6 — Proxy: CANAPE-style TCP MITM with capture and replay.</summary>
public sealed class TcpMitmProxy
{
    private readonly ConcurrentQueue<CapturedMessage> _messages = new();
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;

    public int ListenPort { get; private set; }
    public string TargetHost { get; private set; } = "127.0.0.1";
    public int TargetPort { get; private set; } = 9999;
    public string? Tag { get; private set; }
    public bool IsRunning => _acceptLoop is { IsCompleted: false };

    public IReadOnlyList<CapturedMessage> Messages => _messages.ToArray();

    public bool Start(string targetHost, int targetPort, int listenPort, string? tag = null)
    {
        if (IsRunning)
            return false;

        TargetHost = targetHost;
        TargetPort = targetPort;
        ListenPort = listenPort;
        Tag = tag;
        _cts = new CancellationTokenSource();
        _listener = new TcpListener(IPAddress.Loopback, listenPort);
        _listener.Start();
        _acceptLoop = AcceptLoopAsync(_cts.Token);
        return true;
    }

    public async Task StopAsync()
    {
        _cts?.Cancel();
        _listener?.Stop();
        if (_acceptLoop is not null)
        {
            try { await _acceptLoop; }
            catch (OperationCanceledException) { /* expected */ }
        }
        _acceptLoop = null;
        _listener = null;
    }

    public CapturedMessage? GetMessage(Guid id) =>
        _messages.FirstOrDefault(m => m.Id == id);

    public byte[]? GetPayloadForReplay(Guid id, string? editedHex)
    {
        if (!string.IsNullOrWhiteSpace(editedHex))
        {
            var parts = editedHex.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            return parts.Select(p => Convert.ToByte(p, 16)).ToArray();
        }
        return GetMessage(id)?.Data;
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && _listener is not null)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                break;
            }

            _ = Task.Run(() => RelayAsync(client, cancellationToken), cancellationToken);
        }
    }

    private async Task RelayAsync(TcpClient client, CancellationToken cancellationToken)
    {
        using (client)
        {
            try
            {
                using var upstream = new TcpClient();
                await upstream.ConnectAsync(TargetHost, TargetPort, cancellationToken);

                var clientStream = client.GetStream();
                var upstreamStream = upstream.GetStream();

                var c2s = PumpAsync(clientStream, upstreamStream, "client→target", cancellationToken);
                var s2c = PumpAsync(upstreamStream, clientStream, "target→client", cancellationToken);
                await Task.WhenAny(c2s, s2c);
            }
            catch
            {
                // connection ended
            }
        }
    }

    private async Task PumpAsync(NetworkStream source, NetworkStream dest, string direction, CancellationToken cancellationToken)
    {
        var buffer = new byte[8192];
        while (!cancellationToken.IsCancellationRequested)
        {
            int read;
            try { read = await source.ReadAsync(buffer, cancellationToken); }
            catch { break; }
            if (read <= 0)
                break;

            var chunk = buffer.AsMemory(0, read).ToArray();
            Capture(direction, chunk);
            try { await dest.WriteAsync(chunk, cancellationToken); }
            catch { break; }
        }
    }

    private void Capture(string direction, byte[] data)
    {
        _messages.Enqueue(new CapturedMessage(
            Guid.NewGuid(),
            direction,
            DateTimeOffset.UtcNow,
            data,
            Tag));

        while (_messages.Count > 500 && _messages.TryDequeue(out _))
        {
            // ring cap
        }
    }
}

public sealed class ProxyManager
{
    private readonly TcpMitmProxy _proxy = new();
    private string? _lastMessage;

    public ProxyStatusDto Status => new(
        _proxy.IsRunning,
        _proxy.ListenPort,
        _proxy.TargetHost,
        _proxy.TargetPort,
        _proxy.Messages.Count,
        _lastMessage);

    public bool Start(ProxyStartRequest request)
    {
        var ok = _proxy.Start(request.TargetHost, request.TargetPort, request.ListenPort, request.Tag);
        if (ok)
            _lastMessage = $"Listening on 127.0.0.1:{request.ListenPort} → {request.TargetHost}:{request.TargetPort}";
        return ok;
    }

    public Task StopAsync()
    {
        _lastMessage = "Proxy stopped";
        return _proxy.StopAsync();
    }

    public IReadOnlyList<CapturedMessage> Messages() => _proxy.Messages;

    public async Task<bool> ReplayAsync(Guid messageId, string? editedHex, CancellationToken cancellationToken = default)
    {
        var payload = _proxy.GetPayloadForReplay(messageId, editedHex);
        if (payload is null)
            return false;

        using var client = new TcpClient();
        await client.ConnectAsync(_proxy.TargetHost, _proxy.TargetPort, cancellationToken);
        await using var stream = client.GetStream();
        await stream.WriteAsync(payload, cancellationToken);
        await stream.FlushAsync(cancellationToken);
        _lastMessage = $"Replayed {payload.Length} bytes to target";
        return true;
    }
}
