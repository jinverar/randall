using System.Diagnostics;

namespace Randall.Infrastructure;

/// <summary>
/// Sysinternals DebugView bookend — capture OutputDebugString / Win32 debug output to a log
/// under the run journal. Soft-fails when Dbgview.exe is missing.
/// </summary>
public sealed class DebugViewCapture : IDisposable
{
    private Process? _process;
    private bool _disposed;

    public string LogPath { get; }
    public string MetaPath { get; }
    public string? ExecutablePath { get; }
    public bool IsRunning => _process is { HasExited: false };
    public string? LastError { get; private set; }

    private DebugViewCapture(string logPath, string metaPath, string? executablePath)
    {
        LogPath = logPath;
        MetaPath = metaPath;
        ExecutablePath = executablePath;
    }

    public static string? DiscoverExecutable(string? repoRoot = null) =>
        SysinternalsToolPaths.FindDebugView(repoRoot);

    /// <summary>
    /// Start DebugView minimized, Win32 OutputDebugString capture, logging to file.
    /// Returns an object even when missing so callers can warn without failing the campaign.
    /// </summary>
    public static DebugViewCapture TryStart(string runDirectory, string? repoRoot = null)
    {
        Directory.CreateDirectory(runDirectory);
        var log = Path.Combine(runDirectory, "debugview.log");
        var meta = Path.Combine(runDirectory, "debugview-capture.txt");
        var exe = DiscoverExecutable(repoRoot);

        if (exe is null)
        {
            var missing = new DebugViewCapture(log, meta, null)
            {
                LastError = "Dbgview.exe not found (tools/ or PATH) — copy from Sysinternals Suite",
            };
            TryWriteMeta(missing, "skipped — DebugView not found");
            return missing;
        }

        if (!OperatingSystem.IsWindows())
        {
            var unsupported = new DebugViewCapture(log, meta, exe)
            {
                LastError = "DebugView capture is Windows-only",
            };
            TryWriteMeta(unsupported, "skipped — not Windows");
            return unsupported;
        }

        // Best-effort: close any prior instance so the log file is free.
        try
        {
            foreach (var name in new[] { "Dbgview", "dbgview", "Dbgview64" })
            {
                foreach (var p in Process.GetProcessesByName(name))
                {
                    try
                    {
                        p.Kill(entireProcessTree: true);
                        p.WaitForExit(3000);
                    }
                    catch
                    {
                        /* ignore */
                    }
                    finally
                    {
                        p.Dispose();
                    }
                }
            }
        }
        catch
        {
            /* ignore */
        }

        if (File.Exists(log))
        {
            try { File.Delete(log); }
            catch { /* ignore */ }
        }

        var capture = new DebugViewCapture(log, meta, exe);
        try
        {
            // /t tray · /o Win32 OutputDebugString · /l logfile · /a append
            capture._process = Process.Start(new ProcessStartInfo
            {
                FileName = exe,
                Arguments = $"/accepteula /t /o /l \"{log}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (capture._process is null)
            {
                capture.LastError = "failed to start DebugView";
                TryWriteMeta(capture, "start failed");
                return capture;
            }

            TryWriteMeta(capture, "running");
        }
        catch (Exception ex)
        {
            capture.LastError = ex.Message;
            TryWriteMeta(capture, "start exception");
        }

        return capture;
    }

    public void Stop()
    {
        if (_process is null)
        {
            TryWriteMeta(this, File.Exists(LogPath) ? "stopped — log present" : "stopped");
            return;
        }

        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
                _process.WaitForExit(5000);
            }
        }
        catch (Exception ex)
        {
            LastError ??= ex.Message;
        }
        finally
        {
            _process.Dispose();
            _process = null;
        }

        TryWriteMeta(this, File.Exists(LogPath) && new FileInfo(LogPath).Length > 0
            ? "stopped — log saved"
            : "stopped — empty or missing log (target may not use OutputDebugString)");
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
    }

    private static void TryWriteMeta(DebugViewCapture capture, string status)
    {
        try
        {
            File.WriteAllText(capture.MetaPath,
                $"DebugView capture: {status}\n" +
                $"Executable: {capture.ExecutablePath ?? "(missing)"}\n" +
                $"Log: {capture.LogPath}\n" +
                (capture.LastError is not null ? $"Error: {capture.LastError}\n" : "") +
                "Captures Win32 OutputDebugString (/o). Kernel DbgPrint needs /k + elevation (not armed by default).\n");
        }
        catch
        {
            /* ignore */
        }
    }
}
