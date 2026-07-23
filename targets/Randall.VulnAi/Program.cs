using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Randall.VulnAi;

/// <summary>
/// Intentionally vulnerable fictional AI-gateway lab (RAG1) — teaching target only.
/// Models common LLM-codegen mistakes (length-lie, auth-skip, tool-bridge, mem-classic).
/// Not an LLM, inference runtime, OpenAI/Anthropic API, or agent framework.
/// LAB USE ONLY — loopback by default; no model calls, no tool execution, no shell.
/// </summary>
internal static class Program
{
    private const int CrashExit = 139;

    private const byte TypeInfer = 0x01;
    private const byte TypeTool = 0x02;
    private const byte TypeAdmin = 0x03;

    private static bool _authed;

    public static int Main(string[] args)
    {
        var port = 18765;
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

        Console.WriteLine($"Randall VulnAi RAG1 AI-gateway lab on {host}:{port} (lab only; --host 0.0.0.0 to expose)");
        Console.WriteLine("Randall VulnAi: INFER / TOOL / ADMIN — teaching crashes only; not a real LLM API.");

        using var listener = new TcpListener(host, port);
        listener.Start();

        while (true)
        {
            try
            {
                using var client = listener.AcceptTcpClient();
                using var stream = client.GetStream();
                stream.ReadTimeout = 5000;
                _authed = false;
                WriteAscii(stream, "RAG1 AI READY\r\n");
                HandleSession(stream);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"tcp: {ex.Message}");
            }
        }
    }

    private static void HandleSession(NetworkStream stream)
    {
        while (true)
        {
            if (!TryReadPacket(stream, out var type, out var body))
                return;

            switch (type)
            {
                case TypeInfer:
                    HandleInfer(body);
                    WriteAscii(stream, "INFER OK\r\n");
                    break;
                case TypeTool:
                    HandleTool(body);
                    WriteAscii(stream, "TOOL OK\r\n");
                    break;
                case TypeAdmin:
                    HandleAdmin(body);
                    WriteAscii(stream, "ADMIN OK\r\n");
                    break;
                default:
                    WriteAscii(stream, "ERR type\r\n");
                    break;
            }
        }
    }

    /// <summary>Frame: type_u8 | rem_len_u16_BE | body[rem_len]</summary>
    private static bool TryReadPacket(NetworkStream stream, out byte type, out byte[] body)
    {
        type = 0;
        body = [];
        var hdr = new byte[3];
        if (!ReadExact(stream, hdr))
            return false;
        type = hdr[0];
        var rem = BinaryPrimitives.ReadUInt16BigEndian(hdr.AsSpan(1, 2));
        if (rem > 1024)
            Environment.Exit(CrashExit);
        body = new byte[rem];
        return rem == 0 || ReadExact(stream, body);
    }

    // BEGIN AI
    // AI-GENERATED: naive inference handler — trusts client prompt_len (length-lie / mem-classic).
    private static void HandleInfer(ReadOnlySpan<byte> body)
    {
        if (body.Length < 2)
            return;
        var promptLen = BinaryPrimitives.ReadUInt16BigEndian(body);
        var prompt = body.Length > 2 ? body[2..] : ReadOnlySpan<byte>.Empty;
        // Happy path only — no bounds check against stack slot.
        if (promptLen > 64 || prompt.Length > 64)
            Environment.Exit(CrashExit);
        CopyOverflow(prompt, stackSize: 64, take: Math.Min(promptLen, prompt.Length));
    }
    // END AI

    // BEGIN AI
    // AI-GENERATED: tool-bridge — concatenates name+args with weak caps (output-bridge / path-inject shape).
    private static void HandleTool(ReadOnlySpan<byte> body)
    {
        if (body.Length < 2)
            return;
        var nameLen = BinaryPrimitives.ReadUInt16BigEndian(body);
        if (nameLen > 256)
            Environment.Exit(CrashExit);
        if (body.Length < 2 + nameLen + 2)
            return;
        var name = body.Slice(2, nameLen);
        var argsLen = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(2 + nameLen, 2));
        var args = body.Length > 4 + nameLen ? body[(4 + nameLen)..] : ReadOnlySpan<byte>.Empty;

        var nameStr = Encoding.UTF8.GetString(name);
        // Stub "accepts" traversal / shell-shaped tokens then overflows the join buffer.
        if (nameStr.Contains("..", StringComparison.Ordinal) || nameStr.Contains(';') || nameStr.Contains('|'))
        {
            if (nameLen + Math.Min(argsLen, args.Length) > 48)
                Environment.Exit(CrashExit);
        }

        if (argsLen > 128 || args.Length > 128)
            Environment.Exit(CrashExit);

        CopyOverflow(args, stackSize: 128, take: Math.Min(argsLen, args.Length));
    }
    // END AI

    // BEGIN AI
    // AI-GENERATED: admin handler — auth-skip happy path (always OK if role looks admin).
    private static void HandleAdmin(ReadOnlySpan<byte> body)
    {
        if (body.Length < 2)
            return;
        var tokenLen = BinaryPrimitives.ReadUInt16BigEndian(body);
        var token = body.Length > 2 ? body[2..] : ReadOnlySpan<byte>.Empty;
        var role = Encoding.UTF8.GetString(token.Length > tokenLen ? token[..tokenLen] : token);

        // Missing authz: elevates on string match alone.
        if (role.Contains("admin", StringComparison.OrdinalIgnoreCase) ||
            role.Contains("role=admin", StringComparison.OrdinalIgnoreCase))
        {
            _authed = true;
        }

        // Still no real gate — oversized "admin" token crashes the stub buffer.
        if (!_authed && tokenLen > 32)
        {
            // Would-be deny path also trusts length.
        }

        if (tokenLen > 32 || token.Length > 32)
            Environment.Exit(CrashExit);

        CopyOverflow(token, stackSize: 32, take: Math.Min(tokenLen, token.Length));
    }
    // END AI

    private static unsafe void CopyOverflow(ReadOnlySpan<byte> src, int stackSize, int take)
    {
        var buf = stackalloc byte[stackSize];
        var n = Math.Min(take, src.Length);
        for (var i = 0; i < n; i++)
            buf[i] = src[i];
    }

    private static bool ReadExact(NetworkStream stream, Span<byte> dest)
    {
        var off = 0;
        while (off < dest.Length)
        {
            int n;
            try { n = stream.Read(dest[off..]); }
            catch { return false; }
            if (n <= 0)
                return false;
            off += n;
        }
        return true;
    }

    private static void WriteAscii(NetworkStream stream, string s)
    {
        var bytes = Encoding.ASCII.GetBytes(s);
        stream.Write(bytes, 0, bytes.Length);
    }
}
