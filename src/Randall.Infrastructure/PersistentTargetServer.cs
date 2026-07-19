using System.Diagnostics;
using System.Runtime.InteropServices;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Warm / persistent out-of-process target — one long-lived process fed many
/// length-prefixed stdin cases (Randall persistent stdio protocol).
/// <para>
/// <c>forkServer: true</c> on Windows uses the same warm worker (no Unix
/// <c>fork</c>). Classic AFL <c>FORKSRV_FD</c> handshake is Linux-oriented and
/// reserved for a future native shim; see docs/PERSISTENT.md.
/// </para>
/// </summary>
public sealed class PersistentTargetServer : IAsyncDisposable
{
    private readonly ProjectConfig _project;
    private readonly string _yamlPath;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Process? _proc;
    private string _mode = "stdio-persistent";

    public string Mode => _mode;
    public int IterationsOnWorker { get; private set; }

    private PersistentTargetServer(ProjectConfig project, string yamlPath)
    {
        _project = project;
        _yamlPath = yamlPath;
    }

    public static bool ShouldUse(ProjectConfig project)
    {
        if (InProcessSession.IsInProcess(project))
            return false;
        // Out-of-process: opt-in only (null/false = cold spawn per case via normal runners).
        var persistent = project.Fuzz.Persistent ?? false;
        var forkServer = project.Fuzz.ForkServer ?? false;
        if (!persistent && !forkServer)
            return false;
        var kind = project.Kind.Trim().ToLowerInvariant();
        return kind is "stdio" or "file";
    }

    public static PersistentTargetServer Start(ProjectConfig project, string yamlPath)
    {
        var server = new PersistentTargetServer(project, yamlPath);
        var forkServer = project.Fuzz.ForkServer ?? project.Fuzz.Persistent ?? false;
        server._mode = forkServer
            ? (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? "warm-stdio (forkServer/Windows)"
                : "warm-stdio (forkServer)")
            : "stdio-persistent";
        server.EnsureWorker();
        return server;
    }

    public async Task<TargetRunResult> RunAsync(byte[] payload, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            EnsureWorker();
            var result = await SendStdioAsync(payload, ct);
            IterationsOnWorker++;
            var detail = result.Detail + $" [{_mode} n={IterationsOnWorker}]";
            if (result.Crashed)
            {
                KillWorker();
                IterationsOnWorker = 0;
            }

            return result with { Detail = detail };
        }
        finally
        {
            _gate.Release();
        }
    }

    private void EnsureWorker()
    {
        if (_proc is { HasExited: false })
            return;
        KillWorker();
        _proc = StartStdioProcess();
    }

    private Process StartStdioProcess()
    {
        var exe = _project.Target.Executable;
        if (string.IsNullOrWhiteSpace(exe))
            throw new InvalidOperationException("Persistent/fork-server mode needs target.executable");

        exe = ProjectLoader.ResolvePath(_yamlPath, exe);
        if (!File.Exists(exe))
            throw new FileNotFoundException("Persistent target not found", exe);

        var workDir = string.IsNullOrWhiteSpace(_project.Target.WorkingDirectory)
            ? Path.GetDirectoryName(exe) ?? ProjectLoader.ResolveProjectRoot(_yamlPath)
            : ProjectLoader.ResolvePath(_yamlPath, _project.Target.WorkingDirectory);

        var args = _project.Target.Args
            .Where(a => !a.Contains("{file}", StringComparison.OrdinalIgnoreCase))
            .ToList();

        var psi = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = string.Join(' ', args.Select(EscapeArg)),
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = workDir,
            CreateNoWindow = true,
        };
        psi.Environment["RANDALL_PERSISTENT"] = "1";
        if (_project.Fuzz.ForkServer ?? false)
            psi.Environment["RANDALL_FORK_SERVER"] = "1";

        return Process.Start(psi)
               ?? throw new InvalidOperationException("Failed to start persistent target");
    }

    private async Task<TargetRunResult> SendStdioAsync(byte[] payload, CancellationToken ct)
    {
        var proc = _proc ?? throw new InvalidOperationException("persistent worker missing");
        try
        {
            var stdin = proc.StandardInput.BaseStream;
            await stdin.WriteAsync(BitConverter.GetBytes(payload.Length), ct);
            if (payload.Length > 0)
                await stdin.WriteAsync(payload, ct);
            await stdin.FlushAsync(ct);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(Math.Max(250, _project.Target.TimeoutMs));
            var line = await proc.StandardOutput.ReadLineAsync(cts.Token);

            if (line is null || proc.HasExited)
            {
                var code = proc.HasExited ? proc.ExitCode : (int?)null;
                return new TargetRunResult(true, code, null, "persistent target exited (crash)");
            }

            if (line.StartsWith("OK", StringComparison.OrdinalIgnoreCase))
                return new TargetRunResult(false, 0, null, "persistent ok");
            if (line.StartsWith("CRASH", StringComparison.OrdinalIgnoreCase))
                return new TargetRunResult(true, null, null, $"persistent: {line}");

            return new TargetRunResult(false, null, null, line);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new TargetRunResult(true, null, null, "persistent target timeout");
        }
        catch (Exception ex) when (proc.HasExited)
        {
            return new TargetRunResult(true, proc.ExitCode, null, $"persistent target died: {ex.Message}");
        }
    }

    private void KillWorker()
    {
        try
        {
            if (_proc is not null)
            {
                try
                {
                    if (!_proc.HasExited)
                        _proc.Kill(entireProcessTree: true);
                }
                catch { /* ignore */ }
                _proc.Dispose();
                _proc = null;
            }
        }
        catch { /* ignore */ }
    }

    public ValueTask DisposeAsync()
    {
        KillWorker();
        _gate.Dispose();
        return ValueTask.CompletedTask;
    }

    private static string EscapeArg(string a) =>
        a.Contains(' ') || a.Contains('"') ? $"\"{a.Replace("\"", "\\\"")}\"" : a;
}
