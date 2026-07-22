using System.Diagnostics;
using System.Net.Sockets;
using Randall.Contracts;

namespace Randall.Infrastructure;

public sealed record TargetRunResult(
    bool Crashed,
    int? ExitCode,
    string? MiniDumpPath,
    string Detail,
    byte[]? ResponseBytes = null,
    /// <summary>Optional function/stage hits from a cooperative file target (e.g. ReelDeck).</summary>
    IReadOnlyList<string>? PathHits = null);

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
        if (ProjectKinds.IsTcpLike(project))
        {
            if (project.Fuzz.SyncContentLength || ProjectKinds.IsHttp(project))
                payload = HttpFraming.TrySyncContentLength(payload);
            return await RunTcpAsync(project, yamlPath, longLivedServer, payload, tcpOptions, cancellationToken);
        }

        if (ProjectKinds.IsUdp(project))
            return await RunUdpAsync(project, longLivedServer, payload, cancellationToken);
        return await RunFileAsync(project, yamlPath, payload, cancellationToken);
    }

    public static Process? StartTarget(
        ProjectConfig project,
        string yamlPath,
        string? filePath,
        string? pathLogEnv = null)
    {
        var exe = project.Target.Executable;
        if (string.IsNullOrWhiteSpace(exe))
            return null;

        var declared = ProjectLoader.ResolvePath(yamlPath, exe);
        var existing = ExecutableResolver.FindExisting(declared);
        if (existing is null)
        {
            Console.Error.WriteLine($"Target not found: {declared}");
            return null;
        }

        exe = existing;

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

        // Cooperative file targets (ReelDeck) write function/stage hits here for path stalking.
        if (!string.IsNullOrWhiteSpace(pathLogEnv))
            psi.Environment["REELDECK_PATHLOG"] = pathLogEnv;

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

        var pathLog = tempFile + ".paths";
        using var process = StartTarget(project, yamlPath, tempFile, pathLogEnv: pathLog);
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
            dumpPath = CrashDumpWriter.TryWrite(process, dumpsDir, $"hang_{DateTime.UtcNow:yyyyMMdd_HHmmss}");
            process.Kill(entireProcessTree: true);
            try { File.Delete(tempFile); } catch { /* ignore */ }
            try { File.Delete(pathLog); } catch { /* ignore */ }
            return new TargetRunResult(true, null, dumpPath, "hang/timeout");
        }

        IReadOnlyList<string>? pathHits = null;
        if (File.Exists(pathLog))
        {
            try
            {
                pathHits = File.ReadAllLines(pathLog)
                    .Select(l => l.Trim())
                    .Where(l => l.Length > 0)
                    .Distinct(StringComparer.Ordinal)
                    .ToList();
            }
            catch { /* ignore */ }
            try { File.Delete(pathLog); } catch { /* ignore */ }
        }

        try { File.Delete(tempFile); } catch { /* ignore */ }

        var code = process.ExitCode;
        var crashed = IsCrashExitCode(code);
        if (crashed)
        {
            dumpPath = CrashDumpWriter.TryWrite(
                process, dumpsDir, $"file_{DateTime.UtcNow:yyyyMMdd_HHmmss}", allowExited: true);
        }

        var detail = crashed ? "abnormal exit" : "ok";
        if (pathHits is { Count: > 0 })
            detail =
                $"{detail}; paths={pathHits.Count}:{string.Join(',', pathHits.Take(16))}" +
                (pathHits.Count > 16 ? ",…" : "");

        return new TargetRunResult(crashed, code, dumpPath, detail, PathHits: pathHits);
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
            return await ClassifyTcpTransportFailureAsync(
                project, server, yamlPath, lastResponse, ex, cancellationToken);
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

        // Processes attached by PID ("Already running") cannot always query HasExited/ExitCode.
        bool exited;
        try { exited = server.HasExited; }
        catch (InvalidOperationException)
        {
            return new TargetRunResult(false, null, null, "ok", lastResponse);
        }

        for (var attempt = 0; attempt < 5 && !exited; attempt++)
        {
            await Task.Delay(50, cancellationToken);
            try { exited = server.HasExited; }
            catch (InvalidOperationException)
            {
                return new TargetRunResult(false, null, null, "ok", lastResponse);
            }
        }

        if (!exited)
            return new TargetRunResult(false, null, null, "ok", lastResponse);

        int exitCode;
        try { exitCode = server.ExitCode; }
        catch (InvalidOperationException)
        {
            return new TargetRunResult(true, null, null, "server exited (exit code unavailable)", lastResponse);
        }

        // Bind/start failures (e.g. WSAEADDRINUSE 10048) are infrastructure — not fuzz findings.
        if (IsInfrastructureExitCode(exitCode))
        {
            return new TargetRunResult(
                false, exitCode, null,
                $"server exited (bind/start failure code {exitCode})", lastResponse);
        }

        string? dumpPath = null;
        if (yamlPath is not null)
        {
            var dumpsDir = Path.Combine(
                ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CrashesDir), "dumps");
            // Always attempt platform dump on TCP server death — Linux cores need the pid even
            // when the exit code is a plain non-zero (native SIGSEGV is typically 128+sig).
            dumpPath = CrashDumpWriter.TryWrite(
                server, dumpsDir, $"tcp_{server.Id}_{DateTime.UtcNow:yyyyMMdd_HHmmssfff}",
                allowExited: true);
        }

        var detail = DescribeServerExit(exitCode);
        return new TargetRunResult(true, exitCode, dumpPath, detail, lastResponse);
    }

    private static string DescribeServerExit(int exitCode)
    {
        if (exitCode is >= 129 and <= 159)
        {
            var sig = exitCode - 128;
            var name = sig switch
            {
                4 => "SIGILL",
                6 => "SIGABRT",
                7 => "SIGBUS",
                8 => "SIGFPE",
                11 => "SIGSEGV",
                _ => $"signal {sig}",
            };
            return $"server exited ({name} / {exitCode})";
        }

        return exitCode == 0 ? "server exited" : $"server exited (code {exitCode})";
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
            return await ClassifyTcpTransportFailureAsync(
                project, server, yamlPath, lastResponse, ex, cancellationToken);
        }

        return await FinishTcpRun(project, server, yamlPath, lastResponse, cancellationToken);
    }

    /// <summary>
    /// Connect/send failures must not report as <c>ok</c> when the server process is still alive
    /// (common under coverage-TCP when DynamoRIO has not finished binding yet).
    /// </summary>
    private static async Task<TargetRunResult> ClassifyTcpTransportFailureAsync(
        ProjectConfig project,
        Process? server,
        string? yamlPath,
        byte[]? lastResponse,
        Exception ex,
        CancellationToken cancellationToken)
    {
        if (server is null)
            return new TargetRunResult(false, null, null, ex.Message, lastResponse);

        try { await Task.Delay(80, cancellationToken); }
        catch (OperationCanceledException) { throw; }
        catch { /* ignore */ }

        try
        {
            if (!server.HasExited)
                return new TargetRunResult(false, null, null, ex.Message, lastResponse);
        }
        catch
        {
            return new TargetRunResult(false, null, null, ex.Message, lastResponse);
        }

        return await FinishTcpRun(project, server, yamlPath, lastResponse, cancellationToken);
    }

    /// <summary>
    /// Windows NTSTATUS crash codes, or Linux shell-style <c>128+signal</c> (e.g. 139 = SIGSEGV).
    /// Negative non-<c>-1</c> codes stay treated as abnormal (historical Windows path).
    /// </summary>
    public static bool IsCrashExitCode(int code)
    {
        if (code is unchecked((int)0xC0000005) or unchecked((int)0xC0000409))
            return true;
        // Linux / POSIX: abort on fatal signals often surfaces as 128+signum (SIGINT=130 … SIGSYS=159).
        if (code is >= 129 and <= 159)
            return true;
        return code is < 0 and not -1;
    }

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
