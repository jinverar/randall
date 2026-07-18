using System.Diagnostics;
using System.Globalization;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

public sealed record PostStartContext(
    int Pid,
    string SlotId,
    string Executable,
    string? Host,
    int? Port,
    string? CasePath,
    string? WorkingDirectory,
    string? RepoRoot);

public sealed record PostStartStepResult(string Op, bool Ok, string Message);

/// <summary>
/// Declarative post-start pipeline for Target Runtime — wait-port, sleep, exec, tcp/udp send, http-get.
/// Tokens in strings: {pid} {id} {exe} {host} {port} {case} {workdir}
/// </summary>
public static class PostStartRunner
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(15) };

    public static IReadOnlyList<PostStartStepResult> Run(
        IReadOnlyList<PostStartActionConfig> actions,
        PostStartContext ctx,
        IFuzzProgressSink? log = null)
    {
        var results = new List<PostStartStepResult>();
        if (actions.Count == 0)
            return results;

        FuzzAnalystLog.Step(log, $"Running {actions.Count} post-start action(s)");
        foreach (var action in actions)
        {
            var op = (action.Op ?? "").Trim().ToLowerInvariant();
            try
            {
                var r = op switch
                {
                    "wait-port" or "waitport" => WaitPort(action, ctx),
                    "sleep" or "delay" => Sleep(action),
                    "exec" or "run" or "command" => Exec(action, ctx),
                    "tcp-send" or "tcpsend" => TcpSend(action, ctx),
                    "udp-send" or "udpsend" => UdpSend(action, ctx),
                    "http-get" or "httpget" => HttpGet(action, ctx),
                    _ => new PostStartStepResult(op, false, $"Unknown postStart op '{action.Op}'"),
                };
                results.Add(r);
                if (r.Ok)
                    FuzzAnalystLog.Info(log, $"postStart[{op}]: {r.Message}");
                else
                    FuzzAnalystLog.Warn(log, $"postStart[{op}] failed: {r.Message}");
            }
            catch (Exception ex)
            {
                var fail = new PostStartStepResult(op, false, ex.Message);
                results.Add(fail);
                FuzzAnalystLog.Warn(log, $"postStart[{op}] error: {ex.Message}");
            }
        }

        return results;
    }

    private static PostStartStepResult WaitPort(PostStartActionConfig a, PostStartContext ctx)
    {
        var host = Expand(a.Host ?? ctx.Host ?? "127.0.0.1", ctx);
        var port = a.Port ?? ctx.Port ?? 0;
        if (port <= 0)
            return new("wait-port", false, "port required");
        var timeout = TimeSpan.FromMilliseconds(a.TimeoutMs ?? 5000);
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                using var tcp = new TcpClient();
                var task = tcp.ConnectAsync(host, port);
                if (task.Wait(400) && tcp.Connected)
                    return new("wait-port", true, $"{host}:{port} accepting");
            }
            catch { /* retry */ }

            Thread.Sleep(150);
        }

        return new("wait-port", false, $"{host}:{port} not accepting within {timeout.TotalSeconds:0}s");
    }

    private static PostStartStepResult Sleep(PostStartActionConfig a)
    {
        var ms = a.Ms ?? a.TimeoutMs ?? 200;
        Thread.Sleep(Math.Clamp(ms, 0, 60_000));
        return new("sleep", true, $"slept {ms}ms");
    }

    private static PostStartStepResult Exec(PostStartActionConfig a, PostStartContext ctx)
    {
        if (string.IsNullOrWhiteSpace(a.Command))
            return new("exec", false, "command required");

        var cmd = Expand(a.Command, ctx);
        var args = a.Args.Select(x => Expand(x, ctx)).ToList();
        var work = Expand(a.WorkingDirectory ?? ctx.WorkingDirectory ?? ctx.RepoRoot ?? ".", ctx);
        if (!Path.IsPathRooted(cmd) && ctx.RepoRoot is not null)
        {
            var candidate = Path.Combine(ctx.RepoRoot, cmd.Replace('/', Path.DirectorySeparatorChar));
            if (File.Exists(candidate))
                cmd = candidate;
        }

        var psi = new ProcessStartInfo
        {
            FileName = cmd,
            Arguments = string.Join(' ', args.Select(EscapeArg)),
            WorkingDirectory = Directory.Exists(work) ? work : (ctx.RepoRoot ?? "."),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var proc = Process.Start(psi);
        if (proc is null)
            return new("exec", false, "Process.Start returned null");

        var timeout = a.TimeoutMs ?? 30_000;
        if (!proc.WaitForExit(timeout))
        {
            try { proc.Kill(entireProcessTree: true); } catch { /* ignore */ }
            return new("exec", false, $"timed out after {timeout}ms");
        }

        var err = proc.StandardError.ReadToEnd().Trim();
        if (proc.ExitCode != 0)
            return new("exec", false, $"exit {proc.ExitCode}" + (err.Length > 0 ? $": {Truncate(err, 200)}" : ""));
        return new("exec", true, $"exit 0 ({Path.GetFileName(cmd)})");
    }

    private static PostStartStepResult TcpSend(PostStartActionConfig a, PostStartContext ctx)
    {
        var host = Expand(a.Host ?? ctx.Host ?? "127.0.0.1", ctx);
        var port = a.Port ?? ctx.Port ?? 0;
        if (port <= 0)
            return new("tcp-send", false, "port required");
        var data = ResolvePayload(a);
        if (data.Length == 0)
            return new("tcp-send", false, "dataHex or dataText required");

        using var tcp = new TcpClient();
        var connectTask = tcp.ConnectAsync(host, port);
        if (!connectTask.Wait(a.TimeoutMs ?? 3000) || !tcp.Connected)
            return new("tcp-send", false, $"connect failed {host}:{port}");
        using var stream = tcp.GetStream();
        stream.Write(data);
        stream.Flush();
        return new("tcp-send", true, $"sent {data.Length} bytes → {host}:{port}");
    }

    private static PostStartStepResult UdpSend(PostStartActionConfig a, PostStartContext ctx)
    {
        var host = Expand(a.Host ?? ctx.Host ?? "127.0.0.1", ctx);
        var port = a.Port ?? ctx.Port ?? 0;
        if (port <= 0)
            return new("udp-send", false, "port required");
        var data = ResolvePayload(a);
        if (data.Length == 0)
            return new("udp-send", false, "dataHex or dataText required");

        using var udp = new UdpClient();
        udp.Send(data, data.Length, host, port);
        return new("udp-send", true, $"sent {data.Length} bytes → {host}:{port}");
    }

    private static PostStartStepResult HttpGet(PostStartActionConfig a, PostStartContext ctx)
    {
        if (string.IsNullOrWhiteSpace(a.Url))
            return new("http-get", false, "url required");
        var url = Expand(a.Url, ctx);
        using var cts = new CancellationTokenSource(a.TimeoutMs ?? 5000);
        var resp = Http.GetAsync(url, cts.Token).GetAwaiter().GetResult();
        return new("http-get", resp.IsSuccessStatusCode,
            $"{(int)resp.StatusCode} {resp.ReasonPhrase} ← {url}");
    }

    private static byte[] ResolvePayload(PostStartActionConfig a)
    {
        if (!string.IsNullOrWhiteSpace(a.DataHex))
        {
            var hex = Regex.Replace(a.DataHex, @"[^0-9A-Fa-f]", "");
            if (hex.Length % 2 != 0) hex = "0" + hex;
            var bytes = new byte[hex.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
                bytes[i] = byte.Parse(hex.AsSpan(i * 2, 2), NumberStyles.HexNumber);
            return bytes;
        }

        if (!string.IsNullOrEmpty(a.DataText))
            return Encoding.UTF8.GetBytes(a.DataText);
        return [];
    }

    private static string Expand(string? template, PostStartContext ctx)
    {
        if (string.IsNullOrEmpty(template))
            return "";
        return template
            .Replace("{pid}", ctx.Pid.ToString(), StringComparison.OrdinalIgnoreCase)
            .Replace("{id}", ctx.SlotId, StringComparison.OrdinalIgnoreCase)
            .Replace("{exe}", ctx.Executable, StringComparison.OrdinalIgnoreCase)
            .Replace("{host}", ctx.Host ?? "", StringComparison.OrdinalIgnoreCase)
            .Replace("{port}", ctx.Port?.ToString() ?? "", StringComparison.OrdinalIgnoreCase)
            .Replace("{case}", ctx.CasePath ?? "", StringComparison.OrdinalIgnoreCase)
            .Replace("{workdir}", ctx.WorkingDirectory ?? "", StringComparison.OrdinalIgnoreCase);
    }

    private static string EscapeArg(string a) =>
        a.Contains(' ') || a.Contains('"') ? $"\"{a.Replace("\"", "\\\"")}\"" : a;

    private static string Truncate(string s, int n) =>
        s.Length <= n ? s : s[..n] + "…";
}
