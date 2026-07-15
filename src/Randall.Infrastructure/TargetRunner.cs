using System.Diagnostics;
using System.Net.Sockets;
using Randall.Contracts;

namespace Randall.Infrastructure;

public sealed record TargetRunResult(
    bool Crashed,
    int? ExitCode,
    string? MiniDumpPath,
    string Detail);

public static class TargetRunner
{
    public sealed record TcpSendOptions(byte[]? Preamble = null, bool ReadBanner = true);

    public static async Task<TargetRunResult> RunPayloadAsync(
        ProjectConfig project,
        string yamlPath,
        byte[] payload,
        Process? longLivedServer,
        CancellationToken cancellationToken = default,
        TcpSendOptions? tcpOptions = null)
    {
        if (project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase))
            return await RunTcpAsync(project, longLivedServer, payload, tcpOptions, cancellationToken);
        return await RunFileAsync(project, yamlPath, payload, cancellationToken);
    }

    public static Process? StartTarget(ProjectConfig project, string yamlPath, string? filePath)
    {
        var exe = project.Target.Executable;
        if (string.IsNullOrWhiteSpace(exe))
            return null;

        exe = ProjectLoader.ResolvePath(yamlPath, exe);
        if (!File.Exists(exe))
        {
            Console.Error.WriteLine($"Target not found: {exe}");
            return null;
        }

        var args = project.Target.Args.Select(a =>
            a.Replace("{file}", filePath ?? "", StringComparison.OrdinalIgnoreCase)).ToList();

        var workDir = string.IsNullOrWhiteSpace(project.Target.WorkingDirectory)
            ? Path.GetDirectoryName(exe) ?? ProjectLoader.ResolveProjectRoot(yamlPath)
            : ProjectLoader.ResolvePath(yamlPath, project.Target.WorkingDirectory);

        var psi = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = string.Join(' ', args.Select(EscapeArg)),
            UseShellExecute = false,
            WorkingDirectory = workDir,
        };

        return Process.Start(psi);
    }

    private static async Task<TargetRunResult> RunFileAsync(
        ProjectConfig project,
        string yamlPath,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        var ext = project.Transport.Extension;
        if (!ext.StartsWith('.'))
            ext = "." + ext;
        var tempDir = Path.Combine(ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CorpusDir), "_tmp");
        Directory.CreateDirectory(tempDir);
        var tempFile = Path.Combine(tempDir, $"fuzz_{Guid.NewGuid():N}{ext}");
        await File.WriteAllBytesAsync(tempFile, payload, cancellationToken);

        using var process = StartTarget(project, yamlPath, tempFile);
        if (process is null)
        {
            try { File.Delete(tempFile); } catch { /* ignore */ }
            return new TargetRunResult(false, null, null, "target not found");
        }

        var dumpsDir = Path.Combine(ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CrashesDir), "dumps");
        var exited = await WaitForExitAsync(process, project.Target.TimeoutMs, cancellationToken);
        string? dumpPath = null;

        if (!exited)
        {
            dumpPath = MiniDumpWriter.TryWriteDump(process, dumpsDir, $"hang_{DateTime.UtcNow:yyyyMMdd_HHmmss}");
            process.Kill(entireProcessTree: true);
            try { File.Delete(tempFile); } catch { /* ignore */ }
            return new TargetRunResult(true, null, dumpPath, "hang/timeout");
        }

        try { File.Delete(tempFile); } catch { /* ignore */ }

        var code = process.ExitCode;
        var crashed = IsCrashExitCode(code);
        return new TargetRunResult(crashed, code, dumpPath, crashed ? "abnormal exit" : "ok");
    }

    private static async Task<TargetRunResult> RunTcpAsync(
        ProjectConfig project,
        Process? server,
        byte[] payload,
        TcpSendOptions? tcpOptions,
        CancellationToken cancellationToken)
    {
        tcpOptions ??= new TcpSendOptions();
        try
        {
            using var client = new TcpClient();
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectCts.CancelAfter(2000);
            try
            {
                await client.ConnectAsync(project.Transport.Host, project.Transport.Port, connectCts.Token);
            }
            catch (OperationCanceledException)
            {
                return new TargetRunResult(false, null, null, "connect timeout");
            }

            await using var stream = client.GetStream();
            var buf = new byte[4096];
            stream.ReadTimeout = project.Transport.ReceiveTimeoutMs;

            if (tcpOptions.ReadBanner)
            {
                try { _ = await stream.ReadAsync(buf, cancellationToken); }
                catch { /* banner optional */ }
            }

            if (tcpOptions.Preamble is { Length: > 0 })
            {
                await stream.WriteAsync(tcpOptions.Preamble, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                try { _ = await stream.ReadAsync(buf, cancellationToken); }
                catch { /* response optional */ }
            }

            await stream.WriteAsync(payload, cancellationToken);
            await stream.FlushAsync(cancellationToken);

            try { _ = await stream.ReadAsync(buf, cancellationToken); }
            catch { /* optional */ }
        }
        catch (Exception ex)
        {
            if (server is null)
                return new TargetRunResult(false, null, null, ex.Message);
        }

        if (server is null)
            return new TargetRunResult(false, null, null, "no server process");

        await Task.Delay(150, cancellationToken);
        if (server.HasExited)
            return new TargetRunResult(true, server.ExitCode, null, "server exited");

        return new TargetRunResult(false, null, null, "ok");
    }

    public static bool IsCrashExitCode(int code) =>
        code is unchecked((int)0xC0000005) or unchecked((int)0xC0000409) or (< 0 and not -1);

    private static string EscapeArg(string arg)
    {
        if (arg.Contains(' ') || arg.Contains('"'))
            return $"\"{arg.Replace("\"", "\\\"")}\"";
        return arg;
    }

    private static async Task<bool> WaitForExitAsync(Process process, int timeoutMs, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        try
        {
            await process.WaitForExitAsync(cts.Token);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }
}
