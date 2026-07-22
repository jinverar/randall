using System.Diagnostics;
using System.Net.Sockets;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Phase C — pwntools-shaped tubes for talking to a target (TCP / UDP / stdio).
/// Scare Floor / session graph still decide <em>what</em> to send; tubes are <em>how</em>.
/// </summary>
public interface ITargetTube : IAsyncDisposable
{
    string Kind { get; }
    string Endpoint { get; }
    Task SendAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default);
    Task<byte[]> RecvAsync(int timeoutMs, CancellationToken cancellationToken = default);
}

public static class TargetTube
{
    public static async Task<ITargetTube> OpenAsync(
        ProjectConfig project,
        CancellationToken cancellationToken = default)
    {
        if (ProjectKinds.IsUdp(project))
            return await UdpTube.ConnectAsync(project.Transport, cancellationToken);
        if (ProjectKinds.IsTcpLike(project))
            return await TcpTube.ConnectAsync(project.Transport, cancellationToken);
        throw new InvalidOperationException(
            $"No tube for kind '{project.Kind}' — use file/http/tcp harness or TargetTube.OpenStdio.");
    }

    public static StdioTube OpenStdio(Process process) => new(process);
}

public sealed class TcpTube : ITargetTube
{
    private readonly Stream _stream;
    private readonly TransportConfig _transport;

    private TcpTube(Stream stream, TransportConfig transport)
    {
        _stream = stream;
        _transport = transport;
    }

    public string Kind => "tcp";
    public string Endpoint => $"{_transport.Host}:{_transport.Port}";

    public static async Task<TcpTube> ConnectAsync(
        TransportConfig transport,
        CancellationToken cancellationToken = default)
    {
        var stream = await TcpTransport.ConnectAsync(transport, cancellationToken);
        return new TcpTube(stream, transport);
    }

    public async Task SendAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        await _stream.WriteAsync(data, cancellationToken);
        await _stream.FlushAsync(cancellationToken);
    }

    public async Task<byte[]> RecvAsync(int timeoutMs, CancellationToken cancellationToken = default)
    {
        var buf = await TcpTransport.ReadAvailableAsync(_stream, timeoutMs, cancellationToken);
        return buf ?? [];
    }

    public ValueTask DisposeAsync() => _stream.DisposeAsync();
}

public sealed class UdpTube : ITargetTube
{
    private readonly UdpClient _client;
    private readonly TransportConfig _transport;

    private UdpTube(UdpClient client, TransportConfig transport)
    {
        _client = client;
        _transport = transport;
    }

    public string Kind => "udp";
    public string Endpoint => $"{_transport.Host}:{_transport.Port}";

    public static Task<UdpTube> ConnectAsync(
        TransportConfig transport,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var client = new UdpClient();
        client.Connect(transport.Host, transport.Port);
        return Task.FromResult(new UdpTube(client, transport));
    }

    public async Task SendAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default) =>
        await _client.SendAsync(data.ToArray(), cancellationToken);

    public async Task<byte[]> RecvAsync(int timeoutMs, CancellationToken cancellationToken = default)
    {
        if (timeoutMs <= 0)
            return [];
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeoutMs);
        try
        {
            var result = await _client.ReceiveAsync(cts.Token);
            return result.Buffer;
        }
        catch (OperationCanceledException)
        {
            return [];
        }
    }

    public ValueTask DisposeAsync()
    {
        _client.Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>Stdio tube for CLI-style targets (write stdin, optional read stdout).</summary>
public sealed class StdioTube : ITargetTube
{
    private readonly Process _process;

    public StdioTube(Process process)
    {
        _process = process;
        if (!_process.StartInfo.RedirectStandardInput)
            throw new InvalidOperationException("Process must redirect stdin for StdioTube");
    }

    public string Kind => "stdio";
    public string Endpoint => $"pid:{_process.Id}";

    public async Task SendAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        await _process.StandardInput.BaseStream.WriteAsync(data, cancellationToken);
        await _process.StandardInput.BaseStream.FlushAsync(cancellationToken);
    }

    public async Task<byte[]> RecvAsync(int timeoutMs, CancellationToken cancellationToken = default)
    {
        if (!_process.StartInfo.RedirectStandardOutput)
            return [];
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(Math.Max(timeoutMs, 1));
        try
        {
            var buf = new byte[8192];
            var n = await _process.StandardOutput.BaseStream.ReadAsync(buf, cts.Token);
            return n <= 0 ? [] : buf.AsSpan(0, n).ToArray();
        }
        catch (OperationCanceledException)
        {
            return [];
        }
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
