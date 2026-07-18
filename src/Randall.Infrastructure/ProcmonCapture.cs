using System.Diagnostics;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Sysinternals Process Monitor bookends — start a quiet .pml capture for a fuzz run,
/// terminate on stop. Used locally and via agent /api/remote/procmon/* endpoints.
/// </summary>
public sealed class ProcmonCapture : IDisposable
{
    private Process? _process;
    private bool _disposed;

    public string PmlPath { get; }
    public string? ProcmonPath { get; }
    public bool IsRunning => _process is { HasExited: false };
    public string? LastError { get; private set; }

    private ProcmonCapture(string pmlPath, string procmonPath)
    {
        PmlPath = pmlPath;
        ProcmonPath = procmonPath;
    }

    public static string? DiscoverExecutable(string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var tools = Path.Combine(repoRoot, "tools");
        foreach (var name in new[] { "Procmon64.exe", "Procmon.exe", "procmon.exe" })
        {
            var local = Path.Combine(tools, name);
            if (File.Exists(local))
                return local;
        }

        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathEnv.Split(Path.PathSeparator))
        {
            if (string.IsNullOrWhiteSpace(dir)) continue;
            foreach (var name in new[] { "Procmon64.exe", "Procmon.exe", "procmon.exe" })
            {
                var candidate = Path.Combine(dir, name);
                if (File.Exists(candidate))
                    return candidate;
            }
        }

        return null;
    }

    public static ProcmonCapture? TryStart(string backingFile, string? repoRoot = null)
    {
        var exe = DiscoverExecutable(repoRoot);
        if (exe is null)
            return null;

        var dir = Path.GetDirectoryName(Path.GetFullPath(backingFile));
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        // Terminate any previous quiet capture so /BackingFile isn't locked.
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = exe,
                Arguments = "/Terminate /Quiet /AcceptEula",
                UseShellExecute = false,
                CreateNoWindow = true,
            })?.WaitForExit(5000);
        }
        catch { /* ignore */ }

        var capture = new ProcmonCapture(Path.GetFullPath(backingFile), exe);
        try
        {
            capture._process = Process.Start(new ProcessStartInfo
            {
                FileName = exe,
                Arguments = $"/AcceptEula /Quiet /Minimized /BackingFile \"{capture.PmlPath}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (capture._process is null)
            {
                capture.LastError = "failed to start Procmon";
                return capture;
            }
        }
        catch (Exception ex)
        {
            capture.LastError = ex.Message;
        }

        return capture;
    }

    public void Stop()
    {
        if (_process is null)
            return;
        try
        {
            if (ProcmonPath is not null)
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = ProcmonPath,
                    Arguments = "/Terminate /Quiet /AcceptEula",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                })?.WaitForExit(8000);
            }
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
        }

        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
                _process.WaitForExit(3000);
            }
        }
        catch { /* ignore */ }
        finally
        {
            _process.Dispose();
            _process = null;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
    }
}

public sealed record ProcmonStatusDto(
    bool Available,
    string? Executable,
    bool Running,
    string? PmlPath,
    string? Hint);
