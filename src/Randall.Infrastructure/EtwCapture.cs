using System.Diagnostics;

namespace Randall.Infrastructure;

/// <summary>
/// Windows Performance Recorder (WPR) ETW bookend — light FileIO/Registry/DiskIO/Network
/// profiles into an ETL under the run journal. Built into Windows; requires an elevated
/// Randfuzz process (and an allowed performance-profiling policy). Missing/denied → warn + continue.
/// Open later in WPA / PerfView / UIforETW.
/// </summary>
public sealed class EtwCapture : IDisposable
{
    private bool _disposed;
    private bool _stopped;

    /// <summary>WPR / Windows error when performance profiling policy is blocked.</summary>
    public const int ErrorProfilingPolicy = unchecked((int)0xC5585011);

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

        if (!WindowsElevation.IsProcessElevated())
        {
            var unelevated = new EtwCapture(etl, meta)
            {
                LastError = WindowsElevation.AdminHint,
            };
            TryWriteMeta(unelevated, "skipped — not elevated");
            return unelevated;
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
                capture.LastError = FormatStartFailure(code, stdout, stderr);
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

        // Never call wpr -stop unless we actually started a session.
        if (!IsRunning)
            return;

        var exe = DiscoverExecutable();
        if (exe is null)
        {
            IsRunning = false;
            return;
        }

        try
        {
            var (code, stdout, stderr) = RunWpr(
                exe,
                $"-stop \"{EtlPath}\" \"Randfuzz run\"",
                waitMs: 120_000);
            IsRunning = false;
            if (code != 0 && LastError is null)
            {
                LastError = FormatStopFailure(code, stdout, stderr);
            }

            TryWriteMeta(this, File.Exists(EtlPath) ? "stopped — ETL saved" : "stopped — no ETL");
        }
        catch (Exception ex)
        {
            IsRunning = false;
            LastError ??= ex.Message;
            TryWriteMeta(this, "stop exception");
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (IsRunning)
            Stop();
        else
            _stopped = true;
    }

    private static string FormatStartFailure(int code, string stdout, string stderr)
    {
        var detail = CombineOutput(stdout, stderr);
        var unsigned = unchecked((uint)code);

        if (code == ErrorProfilingPolicy ||
            unsigned == 0xC5585011u ||
            detail.Contains("0xc5585011", StringComparison.OrdinalIgnoreCase) ||
            detail.Contains("profile system performance", StringComparison.OrdinalIgnoreCase) ||
            detail.Contains("performance profiling", StringComparison.OrdinalIgnoreCase))
        {
            // One clear line — do not echo WPR's multi-line Profile Ids dump.
            return $"{WindowsElevation.AdminHint}, or enable the Windows performance profiling policy (WPR 0xc5585011)";
        }

        if (detail.Contains("access", StringComparison.OrdinalIgnoreCase) ||
            detail.Contains("elevat", StringComparison.OrdinalIgnoreCase) ||
            detail.Contains("denied", StringComparison.OrdinalIgnoreCase) ||
            code == 5)
        {
            return string.IsNullOrWhiteSpace(detail)
                ? WindowsElevation.AdminHint
                : $"{WindowsElevation.AdminHint} ({TrimOneLine(detail)})";
        }

        return string.IsNullOrWhiteSpace(detail)
            ? $"wpr start exit 0x{unsigned:X8}"
            : TrimOneLine(detail);
    }

    private static string FormatStopFailure(int code, string stdout, string stderr)
    {
        var detail = CombineOutput(stdout, stderr);
        var unsigned = unchecked((uint)code);
        if (code == ErrorProfilingPolicy ||
            unsigned == 0xC5585011u ||
            detail.Contains("0xc5585011", StringComparison.OrdinalIgnoreCase))
        {
            return $"{WindowsElevation.AdminHint}, or enable the Windows performance profiling policy (WPR 0xc5585011)";
        }

        return string.IsNullOrWhiteSpace(detail)
            ? $"wpr stop exit 0x{unsigned:X8}"
            : TrimOneLine(detail);
    }

    private static string CombineOutput(string stdout, string stderr)
    {
        var err = (stderr ?? "").Trim();
        var out_ = (stdout ?? "").Trim();
        if (err.Length > 0 && out_.Length > 0)
            return err + " | " + out_;
        return err.Length > 0 ? err : out_;
    }

    private static string TrimOneLine(string text)
    {
        var line = text.Replace('\r', ' ').Replace('\n', ' ').Trim();
        while (line.Contains("  ", StringComparison.Ordinal))
            line = line.Replace("  ", " ", StringComparison.Ordinal);
        return line.Length > 180 ? line[..177] + "..." : line;
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
                "Requires elevated Randfuzz (Administrator). Manual: wpr -start FileIO.light -start Registry.light -filemode ; wpr -stop fuzz-etw.etl \"note\"\n");
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
