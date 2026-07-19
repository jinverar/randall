using System.Diagnostics;

namespace Randall.Infrastructure;

/// <summary>
/// Windows Packet Monitor bookend — <c>pktmon start/stop</c> into an ETL under the run journal.
/// Built into recent Windows 10/11; often needs elevation. Missing/denied → warn + continue.
/// </summary>
public sealed class PktmonCapture : IDisposable
{
    private Process? _startProbe;
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

        // Stop any prior capture so the ETL path is free.
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
                capture.LastError = string.IsNullOrWhiteSpace(stderr)
                    ? $"pktmon start exit {code}: {stdout.Trim()}"
                    : stderr.Trim();
                if (capture.LastError.Contains("access", StringComparison.OrdinalIgnoreCase) ||
                    capture.LastError.Contains("elevat", StringComparison.OrdinalIgnoreCase) ||
                    code == 5)
                {
                    capture.LastError += " (try elevated console / admin agent)";
                }

                TryWriteMeta(capture, "start failed");
                return capture;
            }

            capture.IsRunning = true;
            capture._startProbe = null;
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

        try
        {
            var (code, stdout, stderr) = RunPktmon(exe, "stop", waitMs: 30_000);
            IsRunning = false;
            if (code != 0 && LastError is null)
            {
                LastError = string.IsNullOrWhiteSpace(stderr)
                    ? $"pktmon stop exit {code}: {stdout.Trim()}"
                    : stderr.Trim();
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
            LastError = ex.Message;
            TryWriteMeta(this, "stop exception");
        }
        finally
        {
            _startProbe?.Dispose();
            _startProbe = null;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (IsRunning || !_stopped)
            Stop();
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
