using System.Diagnostics;

namespace Randall.Infrastructure;

/// <summary>
/// Optional ProcDump <c>-e -ma</c> arm on the target PID for exception dumps when Scream wait
/// is not already attached (only one debugger can attach). Missing ProcDump → warn + continue.
/// </summary>
public sealed class ProcDumpCrashArm : IDisposable
{
    private Process? _process;
    private bool _disposed;

    public string DumpPath { get; }
    public string ProcDumpPath { get; }
    public bool IsRunning => _process is { HasExited: false };
    public string? LastError { get; private set; }

    private ProcDumpCrashArm(string dumpPath, string procDumpPath)
    {
        DumpPath = dumpPath;
        ProcDumpPath = procDumpPath;
    }

    public static ProcDumpCrashArm? TryArm(int pid, string dumpsDir)
    {
        if (!OperatingSystem.IsWindows())
            return null;

        var exe = DebuggerTools.FindProcDump();
        if (exe is null)
            return null;

        Directory.CreateDirectory(dumpsDir);
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmssfff");
        var dumpPath = Path.Combine(dumpsDir, $"procdump_{pid}_{stamp}.dmp");
        var arm = new ProcDumpCrashArm(dumpPath, exe);
        try
        {
            // -e: unhandled exception; -ma: full dump; -n 1: one capture then exit
            arm._process = Process.Start(new ProcessStartInfo
            {
                FileName = exe,
                Arguments = $"-accepteula -ma -e -n 1 -p {pid} \"{dumpPath}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            if (arm._process is null)
            {
                arm.LastError = "failed to start ProcDump";
                return arm;
            }
        }
        catch (Exception ex)
        {
            arm.LastError = ex.Message;
        }

        return arm;
    }

    public string? TryExistingDump()
    {
        if (File.Exists(DumpPath) && new FileInfo(DumpPath).Length > 0)
            return DumpPath;

        var dir = Path.GetDirectoryName(DumpPath);
        var prefix = Path.GetFileNameWithoutExtension(DumpPath);
        if (dir is null || prefix is null)
            return null;

        try
        {
            return Directory.EnumerateFiles(dir, prefix + "*.dmp")
                .OrderByDescending(File.GetLastWriteTimeUtc)
                .FirstOrDefault(f => new FileInfo(f).Length > 0);
        }
        catch
        {
            return null;
        }
    }

    public void Stop()
    {
        if (_process is null)
            return;
        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
                _process.WaitForExit(3000);
            }
        }
        catch
        {
            /* ignore */
        }
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
