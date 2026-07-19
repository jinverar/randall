using System.Diagnostics;

namespace Randall.Infrastructure;

/// <summary>
/// Windows Performance Recorder (WPR) ETW bookend — light FileIO/Registry/DiskIO/Network
/// profiles into an ETL under the run journal. Built into Windows; often needs elevation.
/// Missing/denied → warn + continue. Open later in WPA / PerfView / UIforETW.
/// </summary>
public sealed class EtwCapture : IDisposable
{
    private bool _disposed;
    private bool _stopped;

    public string EtlPath { get; }
    public string MetaPath { get; }
    public bool IsRunning { get; private set; }
    public string? LastError { get; private set; }

    private EtwCapture(string etlPath, string metaPath)
    {
        EtlPath = etlPath;
        MetaPath = metaPath;
    }

    public static string? DiscoverExecutable()
    {
        if (!OperatingSystem.IsWindows())
            return null;

        foreach (var candidate in new[]
                 {
                     Path.Combine(Environment.SystemDirectory, "wpr.exe"),
                     "wpr.exe",
                 })
        {
            if (candidate.Contains(Path.DirectorySeparatorChar) || candidate.Contains('/'))
            {
                if (File.Exists(candidate))
                    return candidate;
                continue;
            }

            var fromPath = FindOnPath(candidate);
            if (fromPath is not null)
                return fromPath;
        }

        return null;
    }

    public static EtwCapture? TryStart(string runDirectory)
    {
        var exe = DiscoverExecutable();
        Directory.CreateDirectory(runDirectory);
        var etl = Path.Combine(runDirectory, "fuzz-etw.etl");
        var meta = Path.Combine(runDirectory, "etw-capture.txt");

        if (exe is null)
        {
            var missing = new EtwCapture(etl, meta)
            {
                LastError = "wpr.exe not found (Windows Performance Recorder — System32)",
            };
            TryWriteMeta(missing, "skipped — wpr not found");
            return missing;
        }

        // Cancel any prior WPR session so start is clean.
        try
        {
            RunWpr(exe, "-cancel", waitMs: 8000);
        }
        catch
        {
            /* ignore */
        }

        if (File.Exists(etl))
        {
            try { File.Delete(etl); }
            catch { /* ignore */ }
        }

        var capture = new EtwCapture(etl, meta);
        try
        {
            // Light profiles ≈ ProcMon categories at lower overhead than GeneralProfile / ProcMon.
            var args =
                "-start FileIO.light -start Registry.light -start DiskIO.light -start Network.light -filemode";
            var (code, stdout, stderr) = RunWpr(exe, args, waitMs: 20_000);
            if (code != 0)
            {
                capture.LastError = string.IsNullOrWhiteSpace(stderr)
                    ? $"wpr start exit {code}: {stdout.Trim()}"
                    : stderr.Trim();
                if (capture.LastError.Contains("access", StringComparison.OrdinalIgnoreCase) ||
                    capture.LastError.Contains("elevat", StringComparison.OrdinalIgnoreCase) ||
                    capture.LastError.Contains("denied", StringComparison.OrdinalIgnoreCase) ||
                    code == 5)
                {
                    capture.LastError += " (try elevated console / admin agent)";
                }

                TryWriteMeta(capture, "start failed");
                return capture;
            }

            capture.IsRunning = true;
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
        if (_stopped) return;
        _stopped = true;

        var exe = DiscoverExecutable();
        if (exe is null)
            return;

        if (!IsRunning && LastError is not null)
            return;

        try
        {
            var (code, stdout, stderr) = RunWpr(
                exe,
                $"-stop \"{EtlPath}\" \"Randfuzz run\"",
                waitMs: 120_000);
            IsRunning = false;
            if (code != 0 && LastError is null)
            {
                LastError = string.IsNullOrWhiteSpace(stderr)
                    ? $"wpr stop exit {code}: {stdout.Trim()}"
                    : stderr.Trim();
            }

            TryWriteMeta(this, File.Exists(EtlPath) ? "stopped — ETL saved" : "stopped — no ETL");
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            TryWriteMeta(this, "stop exception");
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (IsRunning || !_stopped)
            Stop();
    }

    private static (int ExitCode, string Stdout, string Stderr) RunWpr(string exe, string args, int waitMs)
    {
        var psi = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("failed to start wpr");
        var stdout = proc.StandardOutput.ReadToEnd();
        var stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit(waitMs);
        return (proc.ExitCode, stdout, stderr);
    }

    private static void TryWriteMeta(EtwCapture capture, string status)
    {
        try
        {
            File.WriteAllText(capture.MetaPath,
                $"WPR/ETW capture: {status}\n" +
                $"ETL: {capture.EtlPath}\n" +
                "Profiles: FileIO.light + Registry.light + DiskIO.light + Network.light (-filemode)\n" +
                (capture.LastError is not null ? $"Error: {capture.LastError}\n" : "") +
                "Open later: WPA (wpa.exe), PerfView, or UIforETW\n" +
                "Manual: wpr -start FileIO.light -start Registry.light -filemode ; wpr -stop fuzz-etw.etl \"note\"\n");
        }
        catch
        {
            /* ignore */
        }
    }

    private static string? FindOnPath(string fileName)
    {
        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathEnv.Split(Path.PathSeparator))
        {
            if (string.IsNullOrWhiteSpace(dir)) continue;
            var candidate = Path.Combine(dir, fileName);
            if (File.Exists(candidate))
                return candidate;
        }

        return null;
    }
}
