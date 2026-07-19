using System.Diagnostics;
using System.Text;

namespace Randall.Infrastructure;

/// <summary>
/// Sysmon bookend — does <b>not</b> install or restart Sysmon. Records the run window and
/// exports Microsoft-Windows-Sysmon/Operational events into the run journal on stop.
/// Requires Sysmon already installed as a service with a useful config.
/// </summary>
public sealed class SysmonEventCapture : IDisposable
{
    public const string Channel = "Microsoft-Windows-Sysmon/Operational";

    private bool _disposed;
    private bool _exported;

    public DateTimeOffset StartedAtUtc { get; }
    public string EvtxPath { get; }
    public string MetaPath { get; }
    public string? ServiceName { get; }
    public bool Available { get; }
    public string? LastError { get; private set; }
    public bool ExportOk { get; private set; }

    private SysmonEventCapture(
        DateTimeOffset startedAtUtc,
        string evtxPath,
        string metaPath,
        string? serviceName,
        bool available,
        string? lastError)
    {
        StartedAtUtc = startedAtUtc;
        EvtxPath = evtxPath;
        MetaPath = metaPath;
        ServiceName = serviceName;
        Available = available;
        LastError = lastError;
    }

    /// <summary>True when Sysmon service is installed (Sysmon / Sysmon64) or the event channel exists.</summary>
    public static bool IsAvailable(out string? serviceName, out string? hint)
    {
        serviceName = FindSysmonServiceName();
        if (serviceName is not null)
        {
            hint = $"Sysmon service '{serviceName}' present — export uses {Channel}";
            return true;
        }

        if (ChannelExists())
        {
            hint = $"Sysmon channel {Channel} present (service name not found via SCM)";
            return true;
        }

        hint = "Sysmon not installed — install once (sysmon -i config.xml), enable a fuzz-friendly config; " +
               "Randfuzz only exports the run window";
        return false;
    }

    /// <summary>
    /// Arm export for a run directory. Returns a capture object even when Sysmon is missing
    /// so callers can read <see cref="LastError"/> and warn without failing the campaign.
    /// </summary>
    public static SysmonEventCapture TryBegin(string runDirectory)
    {
        Directory.CreateDirectory(runDirectory);
        var started = DateTimeOffset.UtcNow;
        var evtx = Path.Combine(runDirectory, "sysmon-events.evtx");
        var meta = Path.Combine(runDirectory, "sysmon-export.txt");

        if (!OperatingSystem.IsWindows())
        {
            return new SysmonEventCapture(started, evtx, meta, null, false, "Sysmon export is Windows-only");
        }

        if (!IsAvailable(out var serviceName, out var hint))
            return new SysmonEventCapture(started, evtx, meta, null, false, hint);

        var capture = new SysmonEventCapture(started, evtx, meta, serviceName, true, null);
        try
        {
            File.WriteAllText(meta,
                $"Sysmon export armed at {started:O} UTC\n" +
                $"Service: {serviceName ?? "(channel only)"}\n" +
                $"Channel: {Channel}\n" +
                "Note: Sysmon must already be installed/configured; Randfuzz does not start/stop the service.\n");
        }
        catch (Exception ex)
        {
            capture.LastError = ex.Message;
        }

        return capture;
    }

    /// <summary>Export events from <see cref="StartedAtUtc"/> to now into <see cref="EvtxPath"/>.</summary>
    public void StopAndExport()
    {
        if (_exported) return;
        _exported = true;
        if (!Available)
            return;

        var end = DateTimeOffset.UtcNow;
        var startIso = StartedAtUtc.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        var query = $"*[System[TimeCreated[@SystemTime>='{startIso}']]]";

        try
        {
            if (File.Exists(EvtxPath))
                File.Delete(EvtxPath);

            var psi = new ProcessStartInfo
            {
                FileName = "wevtutil",
                Arguments = $"epl \"{Channel}\" \"{EvtxPath}\" /q:\"{query}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var proc = Process.Start(psi);
            if (proc is null)
            {
                LastError = "failed to start wevtutil";
                WriteMeta(end, ok: false);
                return;
            }

            var stdout = proc.StandardOutput.ReadToEnd();
            var stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit(60_000);
            if (proc.ExitCode != 0 || !File.Exists(EvtxPath))
            {
                LastError = string.IsNullOrWhiteSpace(stderr)
                    ? $"wevtutil exit {proc.ExitCode} ({stdout.Trim()})"
                    : stderr.Trim();
                WriteMeta(end, ok: false);
                TryWriteXmlFallback(query);
                return;
            }

            ExportOk = true;
            WriteMeta(end, ok: true);
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            WriteMeta(end, ok: false);
        }
    }

    private void TryWriteXmlFallback(string query)
    {
        try
        {
            var xmlPath = Path.ChangeExtension(EvtxPath, ".xml");
            var psi = new ProcessStartInfo
            {
                FileName = "wevtutil",
                Arguments = $"qe \"{Channel}\" /q:\"{query}\" /f:xml /rd:true",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var proc = Process.Start(psi);
            if (proc is null) return;
            var xml = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(60_000);
            if (proc.ExitCode == 0 && xml.Length > 20)
            {
                File.WriteAllText(xmlPath, xml, Encoding.UTF8);
                ExportOk = true;
                LastError = null;
                File.AppendAllText(MetaPath, $"XML fallback: {xmlPath}\n");
            }
        }
        catch
        {
            /* ignore */
        }
    }

    private void WriteMeta(DateTimeOffset end, bool ok)
    {
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Sysmon export {(ok ? "OK" : "FAILED")}");
            sb.AppendLine($"Window UTC: {StartedAtUtc:O} → {end:O}");
            sb.AppendLine($"Service: {ServiceName ?? "(channel only)"}");
            sb.AppendLine($"Channel: {Channel}");
            sb.AppendLine($"EVTX: {EvtxPath}");
            if (!string.IsNullOrWhiteSpace(LastError))
                sb.AppendLine($"Error: {LastError}");
            sb.AppendLine();
            sb.AppendLine("Sysmon is a system service — enable a config once (e.g. SwiftOnSecurity / custom).");
            sb.AppendLine("Randfuzz only exports events for the fuzz run window; it does not reinstall Sysmon.");
            File.WriteAllText(MetaPath, sb.ToString());
        }
        catch
        {
            /* ignore */
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        StopAndExport();
    }

    private static string? FindSysmonServiceName()
    {
        if (!OperatingSystem.IsWindows())
            return null;

        foreach (var name in new[] { "Sysmon64", "Sysmon", "Sysmon64c" })
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "sc.exe",
                    Arguments = $"query {name}",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                using var proc = Process.Start(psi);
                if (proc is null) continue;
                var stdout = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(4000);
                if (proc.ExitCode == 0 &&
                    stdout.Contains("SERVICE_NAME", StringComparison.OrdinalIgnoreCase))
                    return name;
            }
            catch
            {
                /* next */
            }
        }

        return null;
    }

    private static bool ChannelExists()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "wevtutil",
                Arguments = $"gl \"{Channel}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var proc = Process.Start(psi);
            if (proc is null) return false;
            proc.WaitForExit(5000);
            return proc.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }
}
