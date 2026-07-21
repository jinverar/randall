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
            await using var tube = await TcpTube.ConnectAsync(project.Transport, cancellationToken);

            if (tcpOptions.ReadBanner)
                lastResponse = await tube.RecvAsync(project.Transport.ReceiveTimeoutMs, cancellationToken);

            if (tcpOptions.Preamble is { Length: > 0 })
            {
                await tube.SendAsync(tcpOptions.Preamble, cancellationToken);
                lastResponse = await tube.RecvAsync(project.Transport.ReceiveTimeoutMs, cancellationToken);
            }

            await tube.SendAsync(payload, cancellationToken);
            lastResponse = await tube.RecvAsync(project.Transport.ReceiveTimeoutMs, cancellationToken);

            if (!ResponseMatcher.Matches(lastResponse, tcpOptions.ExpectResponse))
            {
                // Overflows often kill the server before a valid reply — still check process death.
                if (server is not null)
                {
                    var finished = await FinishTcpRun(project, server, yamlPath, lastResponse, cancellationToken);
                    if (finished.Crashed)
                    {
                        return finished with
                        {
                            Detail =
                                $"{finished.Detail}; response mismatch expect={tcpOptions.ExpectResponse} got={ResponseMatcher.Describe(lastResponse)}",
                        };
                    }
                }

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
        // Remote / network-only targets have no local process handle — connection result is enough.
        if (server is null)
            return new TargetRunResult(false, null, null, "ok", lastResponse);

        for (var attempt = 0; attempt < 5; attempt++)
        {
            if (server.HasExited)
                break;
            await Task.Delay(50, cancellationToken);
        }

        if (!server.HasExited)
            return new TargetRunResult(false, null, null, "ok", lastResponse);

        // Bind/start failures (e.g. WSAEADDRINUSE 10048) are infrastructure — not fuzz findings.
        if (IsInfrastructureExitCode(server.ExitCode))
        {
            return new TargetRunResult(
                false, server.ExitCode, null,
                $"server exited (bind/start failure code {server.ExitCode})", lastResponse);
        }

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
            await using var tube = await UdpTube.ConnectAsync(project.Transport, cancellationToken);
            await tube.SendAsync(payload, cancellationToken);
            var response = await tube.RecvAsync(project.Transport.ReceiveTimeoutMs, cancellationToken);

            if (server is not null)
            {
                await Task.Delay(100, cancellationToken);
                if (server.HasExited)
                {
                    return new TargetRunResult(
                        true, server.ExitCode, null, "udp server exited", response);
                }
            }

            return new TargetRunResult(false, null, null, "ok", response.Length == 0 ? null : response);
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
            await using var tube = await TcpTube.ConnectAsync(project.Transport, cancellationToken);

            for (var i = 0; i < steps.Count; i++)
            {
                var step = steps[i];
                if (i == 0 && step.Options.ReadBanner)
                    lastResponse = await tube.RecvAsync(project.Transport.ReceiveTimeoutMs, cancellationToken);

                if (step.Options.Preamble is { Length: > 0 })
                {
                    await tube.SendAsync(step.Options.Preamble, cancellationToken);
                    lastResponse = await tube.RecvAsync(project.Transport.ReceiveTimeoutMs, cancellationToken);
                }

                await tube.SendAsync(step.Payload, cancellationToken);
                lastResponse = await tube.RecvAsync(project.Transport.ReceiveTimeoutMs, cancellationToken);

                if (!ResponseMatcher.Matches(lastResponse, step.Options.ExpectResponse))
                {
                    // Lab overflows often Exit() before writing expectResponse — detect the scream.
                    if (server is not null)
                    {
                        var finished = await FinishTcpRun(
                            project, server, yamlPath, lastResponse, cancellationToken);
                        if (finished.Crashed)
                        {
                            return finished with
                            {
                                Detail =
                                    $"{finished.Detail}; step {i} response mismatch expect={step.Options.ExpectResponse} got={ResponseMatcher.Describe(lastResponse)}",
                            };
                        }
                    }

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

    /// <summary>Port-in-use / bind failures — not target faults under fuzz input.</summary>
    public static bool IsInfrastructureExitCode(int code) =>
        code is 10048 // WSAEADDRINUSE (Windows)
            or 98     // EADDRINUSE (Linux)
            or 48;    // EADDRINUSE (some BSD/macOS)

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
