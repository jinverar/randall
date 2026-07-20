using System.Diagnostics;

namespace Randall.Infrastructure;

/// <summary>
/// Windows Packet Monitor bookend — <c>pktmon start/stop</c> into an ETL under the run journal.
/// Built into recent Windows 10/11; requires an elevated Randfuzz process. Missing/denied → warn + continue.
/// </summary>
public sealed class PktmonCapture : IDisposable
{
    private bool _disposed;
    private bool _stopped;

    public string EtlPath { get; }
    public string MetaPath { get; }
    public bool IsRunning { get; private set; }
    public string? LastError { get; private set; }

    private PktmonCapture(string etlPath, string metaPath)
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
                     Path.Combine(Environment.SystemDirectory, "pktmon.exe"),
                     "pktmon.exe",
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

    public static PktmonCapture? TryStart(string runDirectory)
    {
        var exe = DiscoverExecutable();
        Directory.CreateDirectory(runDirectory);
        var etl = Path.Combine(runDirectory, "fuzz-pktmon.etl");
        var meta = Path.Combine(runDirectory, "pktmon-capture.txt");

        if (exe is null)
        {
            var missing = new PktmonCapture(etl, meta)
            {
                LastError = "pktmon.exe not found (Windows 10 2004+ / Server 2019+)",
            };
            TryWriteMeta(missing, "skipped — pktmon not found");
            return missing;
        }

        if (!WindowsElevation.IsProcessElevated())
        {
            var unelevated = new PktmonCapture(etl, meta)
            {
                LastError = WindowsElevation.AdminHint,
            };
            TryWriteMeta(unelevated, "skipped — not elevated");
            return unelevated;
        }

        // Stop any prior capture so the ETL path is free (best-effort; ignore "no session").
        try
        {
            RunPktmon(exe, "stop", waitMs: 8000);
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

        var capture = new PktmonCapture(etl, meta);
        try
        {
            // --capture: packet capture; --comp nics: NIC components; -f: ETL path
            var (code, stdout, stderr) = RunPktmon(exe, $"start --capture --comp nics -f \"{etl}\"", waitMs: 15_000);
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

        // Never call pktmon stop unless we actually started — avoids
        // "Cannot obtain current state" spam for skipped/failed starts.
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
            var (code, stdout, stderr) = RunPktmon(exe, "stop", waitMs: 30_000);
            IsRunning = false;
            if (code != 0 && LastError is null)
            {
                var detail = CombineOutput(stdout, stderr);
                if (IsNotAvailableMessage(detail))
                    LastError = $"{WindowsElevation.AdminHint} (pktmon: {TrimOneLine(detail)})";
                else
                    LastError = string.IsNullOrWhiteSpace(detail)
                        ? $"pktmon stop exit {code}"
                        : detail;
            }

            // Optional human-readable summary next to the ETL (best-effort).
            if (File.Exists(EtlPath))
            {
                var txt = Path.ChangeExtension(EtlPath, ".txt");
                RunPktmon(exe, $"etl2txt \"{EtlPath}\" -o \"{txt}\"", waitMs: 60_000);
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
        if (IsNotAvailableMessage(detail) ||
            detail.Contains("access", StringComparison.OrdinalIgnoreCase) ||
            detail.Contains("elevat", StringComparison.OrdinalIgnoreCase) ||
            detail.Contains("denied", StringComparison.OrdinalIgnoreCase) ||
            code == 5)
        {
            var tip = WindowsElevation.AdminHint;
            return string.IsNullOrWhiteSpace(detail)
                ? tip
                : $"{tip} ({TrimOneLine(detail)})";
        }

        return string.IsNullOrWhiteSpace(detail)
            ? $"pktmon start exit {code}"
            : detail;
    }

    private static bool IsNotAvailableMessage(string text) =>
        text.Contains("Cannot obtain current state", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("cannot find the file specified", StringComparison.OrdinalIgnoreCase);

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

    private static (int ExitCode, string Stdout, string Stderr) RunPktmon(string exe, string args, int waitMs)
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
        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("failed to start pktmon");
        var stdout = proc.StandardOutput.ReadToEnd();
        var stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit(waitMs);
        return (proc.ExitCode, stdout, stderr);
    }

    private static void TryWriteMeta(PktmonCapture capture, string status)
    {
        try
        {
            File.WriteAllText(capture.MetaPath,
                $"pktmon capture: {status}\n" +
                $"ETL: {capture.EtlPath}\n" +
                (capture.LastError is not null ? $"Error: {capture.LastError}\n" : "") +
                "Convert later: pktmon etl2pcapng <etl> -o fuzz-pktmon.pcapng\n");
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
