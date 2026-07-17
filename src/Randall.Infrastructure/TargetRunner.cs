using System.Diagnostics;
using System.Net.Sockets;
using Randall.Contracts;

namespace Randall.Infrastructure;

public sealed record TargetRunResult(
    bool Crashed,
    int? ExitCode,
    string? MiniDumpPath,
    string Detail,
    byte[]? ResponseBytes = null);

public static class TargetRunner
{
    public sealed record TcpSendOptions(byte[]? Preamble = null, bool ReadBanner = true, string? ExpectResponse = null);

    public static async Task<TargetRunResult> RunPayloadAsync(
        ProjectConfig project,
        string yamlPath,
        byte[] payload,
        Process? longLivedServer,
        CancellationToken cancellationToken = default,
        TcpSendOptions? tcpOptions = null)
    {
        if (project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase))
            return await RunTcpAsync(project, yamlPath, longLivedServer, payload, tcpOptions, cancellationToken);
        if (project.Kind.Equals("udp", StringComparison.OrdinalIgnoreCase))
            return await RunUdpAsync(project, longLivedServer, payload, cancellationToken);
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
        if (crashed)
        {
            dumpPath = MiniDumpWriter.TryWriteDump(
                process, dumpsDir, $"file_{DateTime.UtcNow:yyyyMMdd_HHmmss}");
        }

        return new TargetRunResult(crashed, code, dumpPath, crashed ? "abnormal exit" : "ok");
    }

    private static async Task<TargetRunResult> RunTcpAsync(
        ProjectConfig project,
        string yamlPath,
        Process? server,
        byte[] payload,
        TcpSendOptions? tcpOptions,
        CancellationToken cancellationToken)
    {
        tcpOptions ??= new TcpSendOptions();
        byte[]? lastResponse = null;
        try
        {
            await using var stream = await TcpTransport.ConnectAsync(project.Transport, cancellationToken);

            if (tcpOptions.ReadBanner)
                lastResponse = await TcpTransport.ReadAvailableAsync(
                    stream, project.Transport.ReceiveTimeoutMs, cancellationToken);

            if (tcpOptions.Preamble is { Length: > 0 })
            {
                await stream.WriteAsync(tcpOptions.Preamble, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                lastResponse = await TcpTransport.ReadAvailableAsync(
                    stream, project.Transport.ReceiveTimeoutMs, cancellationToken);
            }

            await stream.WriteAsync(payload, cancellationToken);
            await stream.FlushAsync(cancellationToken);
            lastResponse = await TcpTransport.ReadAvailableAsync(
                stream, project.Transport.ReceiveTimeoutMs, cancellationToken);

            if (!ResponseMatcher.Matches(lastResponse, tcpOptions.ExpectResponse))
            {
                return new TargetRunResult(
                    false,
                    null,
                    null,
                    $"response mismatch expect={tcpOptions.ExpectResponse} got={ResponseMatcher.Describe(lastResponse)}",
                    lastResponse);
            }
        }
        catch (Exception ex)
        {
            if (server is null)
                return new TargetRunResult(false, null, null, ex.Message, lastResponse);
        }

        return await FinishTcpRun(project, server, yamlPath, lastResponse, cancellationToken);
    }

    private static async Task<TargetRunResult> FinishTcpRun(
        ProjectConfig project,
        Process? server,
        string? yamlPath,
        byte[]? lastResponse,
        CancellationToken cancellationToken)
    {
        if (server is null)
            return new TargetRunResult(false, null, null, "no server process", lastResponse);

        for (var attempt = 0; attempt < 5; attempt++)
        {
            if (server.HasExited)
                break;
            await Task.Delay(50, cancellationToken);
        }

        if (!server.HasExited)
            return new TargetRunResult(false, null, null, "ok", lastResponse);

        string? dumpPath = null;
        if (IsCrashExitCode(server.ExitCode) && yamlPath is not null)
        {
            var dumpsDir = Path.Combine(
                ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CrashesDir), "dumps");
            dumpPath = MiniDumpWriter.TryWriteDump(
                server, dumpsDir, $"tcp_{server.Id}_{DateTime.UtcNow:yyyyMMdd_HHmmssfff}", allowExited: true);
        }

        return new TargetRunResult(true, server.ExitCode, dumpPath, "server exited", lastResponse);
    }

    public static Task<TargetRunResult> FinishTcpRunFromGraph(
        ProjectConfig project,
        string yamlPath,
        Process? server,
        byte[]? lastResponse,
        CancellationToken cancellationToken) =>
        FinishTcpRun(project, server, yamlPath, lastResponse, cancellationToken);

    private static async Task<TargetRunResult> RunUdpAsync(
        ProjectConfig project,
        Process? server,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        try
        {
            using var client = new UdpClient();
            client.Connect(project.Transport.Host, project.Transport.Port);
            await client.SendAsync(payload, cancellationToken);

            byte[]? response = null;
            if (project.Transport.ReceiveTimeoutMs > 0)
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(project.Transport.ReceiveTimeoutMs);
                try
                {
                    var result = await client.ReceiveAsync(cts.Token);
                    response = result.Buffer;
                }
                catch (OperationCanceledException) { /* no response ok */ }
            }

            if (server is not null)
            {
                await Task.Delay(100, cancellationToken);
                if (server.HasExited)
                {
                    return new TargetRunResult(
                        true, server.ExitCode, null, "udp server exited", response);
                }
            }

            return new TargetRunResult(false, null, null, "ok", response);
        }
        catch (Exception ex)
        {
            return new TargetRunResult(false, null, null, ex.Message);
        }
    }

    public sealed record TcpStep(byte[] Payload, TcpSendOptions Options);

    public static async Task<TargetRunResult> RunTcpSequenceAsync(
        ProjectConfig project,
        string yamlPath,
        Process? server,
        IReadOnlyList<TcpStep> steps,
        CancellationToken cancellationToken = default)
    {
        if (steps.Count == 0)
            return new TargetRunResult(false, null, null, "empty sequence");

        byte[]? lastResponse = null;
        try
        {
            await using var stream = await TcpTransport.ConnectAsync(project.Transport, cancellationToken);

            for (var i = 0; i < steps.Count; i++)
            {
                var step = steps[i];
                if (i == 0 && step.Options.ReadBanner)
                {
                    lastResponse = await TcpTransport.ReadAvailableAsync(
                        stream, project.Transport.ReceiveTimeoutMs, cancellationToken);
                }

                if (step.Options.Preamble is { Length: > 0 })
                {
                    await stream.WriteAsync(step.Options.Preamble, cancellationToken);
                    await stream.FlushAsync(cancellationToken);
                    lastResponse = await TcpTransport.ReadAvailableAsync(
                        stream, project.Transport.ReceiveTimeoutMs, cancellationToken);
                }

                await stream.WriteAsync(step.Payload, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                lastResponse = await TcpTransport.ReadAvailableAsync(
                    stream, project.Transport.ReceiveTimeoutMs, cancellationToken);

                if (!ResponseMatcher.Matches(lastResponse, step.Options.ExpectResponse))
                {
                    return new TargetRunResult(
                        false,
                        null,
                        null,
                        $"step {i} response mismatch expect={step.Options.ExpectResponse} got={ResponseMatcher.Describe(lastResponse)}",
                        lastResponse);
                }
            }
        }
        catch (Exception ex)
        {
            if (server is null)
                return new TargetRunResult(false, null, null, ex.Message, lastResponse);
        }

        return await FinishTcpRun(project, server, yamlPath, lastResponse, cancellationToken);
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
