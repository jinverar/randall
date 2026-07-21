using System.Diagnostics;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Linux AFL classic forkserver parent (FORKSRV_FD 198/199) via a native helper
/// (<c>randall_forksrv_helper</c>) so the CLR never calls <c>posix_spawn</c>/fork.
/// </summary>
public sealed class AflForkServer : IAsyncDisposable
{
    private readonly Process _helper;
    private readonly int _timeoutMs;
    private bool _ready;

    public string Mode => "afl-forksrv";
    public int IterationsOnWorker { get; private set; }
    public bool IsReady => _ready;

    private AflForkServer(Process helper, int timeoutMs)
    {
        _helper = helper;
        _timeoutMs = timeoutMs;
        _ready = true;
    }

    public static AflForkServer? TryStart(
        ProjectConfig project,
        string yamlPath,
        TimeSpan? handshakeTimeout = null)
    {
        if (!OperatingSystem.IsLinux())
            return null;
        if (string.IsNullOrWhiteSpace(project.Target.Executable))
            return null;

        var helper = FindHelper();
        if (helper is null)
            return null;

        var declared = ProjectLoader.ResolvePath(yamlPath, project.Target.Executable);
        var exe = ExecutableResolver.FindExisting(declared);
        if (exe is null)
            return null;

        var workDir = string.IsNullOrWhiteSpace(project.Target.WorkingDirectory)
            ? Path.GetDirectoryName(exe) ?? ProjectLoader.ResolveProjectRoot(yamlPath)
            : ProjectLoader.ResolvePath(yamlPath, project.Target.WorkingDirectory);

        var inputFile = Path.Combine(
            ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CorpusDir),
            "_forksrv_input.bin");
        Directory.CreateDirectory(Path.GetDirectoryName(inputFile)!);
        File.WriteAllBytes(inputFile, []);

        var args = project.Target.Args
            .Select(a => a.Replace("{file}", inputFile, StringComparison.OrdinalIgnoreCase)
                          .Replace("@@", inputFile, StringComparison.Ordinal))
            .ToList();
        if (args.Count == 0)
            args.Add(inputFile);

        var psi = new ProcessStartInfo
        {
            FileName = helper,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = workDir,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add(inputFile);
        psi.ArgumentList.Add(exe);
        foreach (var a in args)
            psi.ArgumentList.Add(a);
        psi.Environment["RANDALL_FORK_SERVER"] = "1";
        psi.Environment["AFL_OLD_FORKSERVER"] = "1";

        Process? proc = null;
        try
        {
            proc = Process.Start(psi);
            if (proc is null)
                return null;

            using var cts = new CancellationTokenSource(handshakeTimeout ?? TimeSpan.FromSeconds(3));
            var readyTask = proc.StandardOutput.ReadLineAsync(cts.Token);
            var line = readyTask.GetAwaiter().GetResult();
            if (!string.Equals(line, "READY", StringComparison.Ordinal))
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* ignore */ }
                proc.Dispose();
                return null;
            }

            return new AflForkServer(proc, Math.Max(250, project.Target.TimeoutMs));
        }
        catch
        {
            try
            {
                if (proc is { HasExited: false })
                    proc.Kill(entireProcessTree: true);
                proc?.Dispose();
            }
            catch { /* ignore */ }

            return null;
        }
    }

    public async Task<TargetRunResult> RunAsync(byte[] payload, CancellationToken ct)
    {
        if (!_ready || _helper.HasExited)
            return new TargetRunResult(true, null, null, "forksrv helper exited");

        try
        {
            var stdin = _helper.StandardInput.BaseStream;
            await stdin.WriteAsync(BitConverter.GetBytes(payload.Length), ct);
            if (payload.Length > 0)
                await stdin.WriteAsync(payload, ct);
            await stdin.FlushAsync(ct);

            var statusBuf = new byte[4];
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(_timeoutMs);
            var read = 0;
            while (read < 4)
            {
                var n = await _helper.StandardOutput.BaseStream.ReadAsync(
                    statusBuf.AsMemory(read, 4 - read), cts.Token);
                if (n <= 0)
                    return new TargetRunResult(true, null, null, "forksrv status eof");
                read += n;
            }

            IterationsOnWorker++;
            var status = BitConverter.ToInt32(statusBuf, 0);
            var crashed = WaitStatusCrashed(status);
            var exitCode = WaitStatusExitCode(status);
            var detail = crashed
                ? $"forksrv crash status=0x{status:X8}"
                : $"forksrv ok status=0x{status:X8}";
            return new TargetRunResult(crashed, exitCode, null, $"{detail} [{Mode} n={IterationsOnWorker}]");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new TargetRunResult(true, null, null, "forksrv status timeout");
        }
        catch (Exception ex)
        {
            return new TargetRunResult(true, null, null, $"forksrv error: {ex.Message}");
        }
    }

    private static bool WaitStatusCrashed(int status)
    {
        var termSig = status & 0x7f;
        if (termSig is not 0 and not 0x7f)
            return true;
        if ((status & 0x7f) == 0 && ((status & 0xff00) >> 8) != 0)
            return true;
        return false;
    }

    private static int? WaitStatusExitCode(int status)
    {
        var termSig = status & 0x7f;
        if (termSig is not 0 and not 0x7f)
            return 128 + termSig;
        if ((status & 0x7f) == 0)
            return (status & 0xff00) >> 8;
        return status;
    }

    private static string? FindHelper()
    {
        var env = Environment.GetEnvironmentVariable("RANDALL_FORKSRV_HELPER");
        if (!string.IsNullOrWhiteSpace(env) && File.Exists(env))
            return env;

        var root = CrashCatalog.FindRepoRoot();
        if (root is not null)
        {
            foreach (var rel in new[]
                     {
                         Path.Combine("targets", "forksrv-demo", "randall_forksrv_helper"),
                         Path.Combine("tools", "randall_forksrv_helper"),
                     })
            {
                var p = Path.Combine(root, rel);
                if (File.Exists(p))
                    return p;
            }
        }

        return FindOnPath("randall_forksrv_helper");
    }

    private static string? FindOnPath(string name)
    {
        var path = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(dir, name);
            if (File.Exists(candidate))
                return candidate;
        }

        return null;
    }

    public async ValueTask DisposeAsync()
    {
        _ready = false;
        try
        {
            if (!_helper.HasExited)
            {
                try { _helper.StandardInput.Close(); } catch { /* ignore */ }
                try { _helper.Kill(entireProcessTree: true); } catch { /* ignore */ }
            }

            await Task.Delay(50);
        }
        catch { /* ignore */ }
        finally
        {
            try { _helper.Dispose(); } catch { /* ignore */ }
        }
    }
}
