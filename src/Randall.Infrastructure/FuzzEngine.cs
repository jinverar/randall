using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using Randall.Contracts;
using Randall.Core;
using Randall.Infrastructure.Mutators;

namespace Randall.Infrastructure;

public sealed class FuzzEngine
{
    public async Task<FuzzRunResult> RunAsync(
        ProjectConfig project,
        string yamlPath,
        bool dryRun = false,
        CancellationToken cancellationToken = default)
    {
        var mutators = BuiltInMutators.Create(project.Mutators);
        var seeds = LoadAllSeeds(project, yamlPath);
        if (seeds.Count == 0)
            seeds.Add(Array.Empty<byte>());

        var crashStore = new CrashStore(ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CrashesDir));
        crashStore.Ensure();
        Directory.CreateDirectory(ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CorpusDir));

        var crashes = new List<CrashRecord>();
        Process? longLived = null;
        if (project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase) && project.Target.LongLived)
            longLived = StartTarget(project, yamlPath, null);

        var iterations = 0;
        var crashCount = 0;
        var rng = Random.Shared;

        try
        {
            for (var i = 0; i < project.Fuzz.MaxIterations && !cancellationToken.IsCancellationRequested; i++)
            {
                iterations++;
                var seed = seeds[rng.Next(seeds.Count)];
                var mutator = mutators[rng.Next(mutators.Count)];
                var payload = mutator.Mutate(seed).ToArray();
                if (project.Transport.Prefix.Length > 0)
                {
                    var prefix = Encoding.ASCII.GetBytes(project.Transport.Prefix);
                    payload = prefix.Concat(payload).ToArray();
                }

                if (dryRun)
                {
                    Console.WriteLine($"[dry-run] #{iterations} {mutator.Name} len={payload.Length}");
                    continue;
                }

                TargetRunResult result;
                if (project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase))
                    result = await RunTcpIterationAsync(project, longLived, payload, cancellationToken);
                else
                    result = await RunFileIterationAsync(project, yamlPath, payload, cancellationToken);

                if (result.Crashed)
                {
                    crashCount++;
                    var saved = crashStore.Save(project.Name, iterations, mutator.Name, payload, result.ExitCode);
                    Console.WriteLine($"CRASH #{crashCount} iter={iterations} mutator={mutator.Name} saved={saved.InputPath}");
                    crashes.Add(new CrashRecord(
                        saved.Id,
                        payload,
                        saved.InputHash,
                        result.ExitCode?.ToString() ?? "unknown",
                        null,
                        null,
                        0));

                    if (project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase) && project.Target.LongLived)
                    {
                        longLived?.Kill(entireProcessTree: true);
                        longLived?.Dispose();
                        await Task.Delay(300, cancellationToken);
                        longLived = StartTarget(project, yamlPath, null);
                    }
                }
                else if (iterations % 50 == 0)
                {
                    Console.WriteLine($"iter={iterations} ok len={payload.Length}");
                }
            }
        }
        finally
        {
            if (longLived is { HasExited: false })
            {
                longLived.Kill(entireProcessTree: true);
                longLived.Dispose();
            }
        }

        return new FuzzRunResult(iterations, 0, crashCount, crashes);
    }

    private static List<byte[]> LoadAllSeeds(ProjectConfig project, string yamlPath)
    {
        var list = new List<byte[]>();
        foreach (var seed in project.Seeds)
        {
            try
            {
                list.Add(ProjectLoader.LoadSeed(yamlPath, seed));
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Warning: skip seed {seed}: {ex.Message}");
            }
        }
        return list;
    }

    private static async Task<TargetRunResult> RunFileIterationAsync(
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
            return new TargetRunResult(false, null);

        var exited = await WaitForExitAsync(process, project.Target.TimeoutMs, cancellationToken);
        try { File.Delete(tempFile); } catch { /* ignore */ }

        if (!exited)
        {
            process.Kill(entireProcessTree: true);
            return new TargetRunResult(true, null);
        }

        var code = process.ExitCode;
        // Access violation / stack buffer overrun on Windows
        var crashed = code is unchecked((int)0xC0000005) or unchecked((int)0xC0000409)
            or < 0 and not -1;
        return new TargetRunResult(crashed, code);
    }

    private static async Task<TargetRunResult> RunTcpIterationAsync(
        ProjectConfig project,
        Process? server,
        byte[] payload,
        CancellationToken cancellationToken)
    {
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
                return new TargetRunResult(false, null);
            }

            await using var stream = client.GetStream();
            await stream.WriteAsync(payload, cancellationToken);
            await stream.FlushAsync(cancellationToken);

            var buf = new byte[4096];
            stream.ReadTimeout = project.Transport.ReceiveTimeoutMs;
            try
            {
                _ = await stream.ReadAsync(buf, cancellationToken);
            }
            catch { /* banner optional */ }
        }
        catch
        {
            // connection failure may mean server crashed
        }

        if (server is null)
            return new TargetRunResult(false, null);

        await Task.Delay(100, cancellationToken);
        if (server.HasExited)
            return new TargetRunResult(true, server.ExitCode);

        return new TargetRunResult(false, null);
    }

    private static Process? StartTarget(ProjectConfig project, string yamlPath, string? filePath)
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

    private sealed record TargetRunResult(bool Crashed, int? ExitCode);
}
