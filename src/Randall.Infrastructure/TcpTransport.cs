using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Leg 3 — Send: TCP/plain or TLS stream helper.</summary>
public static class TcpTransport
{
    public sealed record SendResult(byte[]? LastResponse, string Detail);

    public static async Task<Stream> ConnectAsync(
        TransportConfig transport,
        CancellationToken cancellationToken = default)
    {
        var client = new TcpClient();
        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectCts.CancelAfter(2000);
        await client.ConnectAsync(transport.Host, transport.Port, connectCts.Token);

        var stream = client.GetStream();
        if (!transport.Tls)
            return new TcpClientStream(client, stream);

        var ssl = new SslStream(stream, false, (_, _, _, _) => transport.TlsInsecure);
        var host = string.IsNullOrWhiteSpace(transport.TlsHost) ? transport.Host : transport.TlsHost;
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = host,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
        }, cancellationToken);

        return new TcpClientStream(client, ssl);
    }

    public static async Task<byte[]?> ReadAvailableAsync(
        Stream stream,
        int receiveTimeoutMs,
        CancellationToken cancellationToken)
    {
        if (receiveTimeoutMs <= 0)
            return null;

        var buf = new byte[4096];
        try
        {
            if (stream.CanTimeout)
                stream.ReadTimeout = receiveTimeoutMs;
            var n = await stream.ReadAsync(buf.AsMemory(0, buf.Length), cancellationToken);
            if (n <= 0)
                return null;
            return buf.AsSpan(0, n).ToArray();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Owns TcpClient; disposes both client and stream on dispose.</summary>
    private sealed class TcpClientStream(TcpClient client, Stream inner) : Stream
    {
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
                client.Dispose();
            }
            base.Dispose(disposing);
        }

        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => inner.CanWrite;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void SetLength(long value) => inner.SetLength(value);
        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            inner.ReadAsync(buffer, offset, count, cancellationToken);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            inner.ReadAsync(buffer, cancellationToken);
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            inner.WriteAsync(buffer, offset, count, cancellationToken);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            inner.WriteAsync(buffer, cancellationToken);
        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
    }
}
