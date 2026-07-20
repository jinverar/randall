using System.Diagnostics;
using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Deterministic stop/dispose for all armed fuzz recorders, plus host-wide orphan cleanup
/// (Procmon / DebugView / ProcDump / WPR / pktmon / tshark) when a run died uncleanly.
/// </summary>
public static class RecordingTeardown
{
    /// <summary>
    /// Stop every armed bookend from a fuzz run. Each step is isolated so one failure
    /// cannot leave the rest running.
    /// </summary>
    public static RecordingStopResultDto DisposeArmed(
        IFuzzProgressSink? progress,
        int? endPid,
        ProcDumpCrashArm? procdumpArm,
        SysinternalsSnapshots? sysinternalsSnap,
        TcpvconCapture? tcpvcon,
        DebugViewCapture? debugView,
        ProcmonCapture? procmon,
        PktmonCapture? pktmon,
        TsharkCapture? tshark,
        EtwCapture? etw)
    {
        var items = new List<RecordingStopItemDto>();

        Safe("procdump", () =>
        {
            if (procdumpArm is null)
                return null;
            var path = procdumpArm.TryExistingDump() ?? procdumpArm.DumpPath;
            var wasRunning = procdumpArm.IsRunning;
            procdumpArm.Dispose();
            return wasRunning || File.Exists(path)
                ? new RecordingStopItemDto("procdump", path, File.Exists(path) ? "stopped" : "disarmed")
                : null;
        }, items);

        Safe("sysinternals", () =>
        {
            if (sysinternalsSnap is null)
                return null;
            var any = sysinternalsSnap.AnyToolFound;
            var dir = sysinternalsSnap.SnapshotDir;
            if (any)
            {
                try { sysinternalsSnap.CaptureDisarm(endPid); }
                catch { /* still dispose */ }
            }

            sysinternalsSnap.Dispose();
            return any
                ? new RecordingStopItemDto("sysinternals", dir, "disarmed")
                : null;
        }, items);

        Safe("tcpvcon", () =>
        {
            if (tcpvcon is null)
                return null;
            var available = tcpvcon.Available;
            var dir = tcpvcon.CaptureDir;
            if (available)
            {
                try { tcpvcon.CaptureDisarm(endPid); }
                catch { /* still dispose */ }
            }

            tcpvcon.Dispose();
            return available
                ? new RecordingStopItemDto("tcpvcon", dir, "disarmed")
                : null;
        }, items);

        Safe("debugview", () =>
        {
            if (debugView is null)
                return null;
            var path = debugView.LogPath;
            var wasRunning = debugView.IsRunning;
            var startError = debugView.LastError;
            debugView.Stop();
            debugView.Dispose();
            if (!wasRunning && startError is not null && !File.Exists(path))
                return null;
            return new RecordingStopItemDto(
                "debugview",
                path,
                File.Exists(path) && new FileInfo(path).Length > 0 ? "stopped → log" : "stopped");
        }, items);

        Safe("procmon", () =>
        {
            if (procmon is null)
                return null;
            var path = procmon.PmlPath;
            var wasRunning = procmon.IsRunning;
            procmon.Stop();
            procmon.Dispose();
            if (!wasRunning && !File.Exists(path))
                return null;
            return new RecordingStopItemDto(
                "procmon",
                path,
                File.Exists(path) ? "stopped → pml" : "stopped");
        }, items);

        Safe("pktmon", () =>
        {
            if (pktmon is null)
                return null;
            var path = pktmon.EtlPath;
            var wasRunning = pktmon.IsRunning;
            // Skip stop when never started (unelevated / start failed) — avoids second error.
            if (wasRunning)
                pktmon.Stop();
            pktmon.Dispose();
            if (!wasRunning && !File.Exists(path))
                return null;
            return new RecordingStopItemDto(
                "pktmon",
                path,
                File.Exists(path) ? "stopped → etl" : "stopped");
        }, items);

        Safe("tshark", () =>
        {
            if (tshark is null)
                return null;
            var path = tshark.PcapPath;
            var wasRunning = tshark.IsRunning;
            tshark.Stop();
            tshark.Dispose();
            if (!wasRunning && !File.Exists(path))
                return null;
            return new RecordingStopItemDto(
                "tshark",
                path,
                File.Exists(path) ? "stopped → pcapng" : "stopped");
        }, items);

        Safe("etw", () =>
        {
            if (etw is null)
                return null;
            var path = etw.EtlPath;
            var wasRunning = etw.IsRunning;
            // Skip stop when never started (unelevated / WPR policy / start failed).
            if (wasRunning)
                etw.Stop();
            etw.Dispose();
            if (!wasRunning && !File.Exists(path))
                return null;
            return new RecordingStopItemDto(
                "etw",
                path,
                File.Exists(path) ? "stopped → etl" : "stopped");
        }, items);

        var message = FormatSummary(items);
        if (items.Count > 0)
            FuzzAnalystLog.Info(progress, message);
        else
            FuzzAnalystLog.Info(progress, "Recording stopped: (no captures were armed)");

        return new RecordingStopResultDto(true, message, items);
    }

    /// <summary>
    /// Host-wide emergency stop: remote Procmon slot, GUI orphans, WPR cancel, pktmon/tshark stop.
    /// Safe to call when no fuzz is running (or after a hard kill left tools behind).
    /// </summary>
    public static RecordingStopResultDto StopHostCaptures(string? repoRoot = null)
    {
        var items = new List<RecordingStopItemDto>();

        Safe("remote-procmon", () =>
        {
            var st = RemoteStalkAgent.Stop(repoRoot);
            return new RecordingStopItemDto(
                "remote-procmon",
                st.PmlPath,
                st.Running ? "still running" : "stopped");
        }, items);

        Safe("procmon", () =>
        {
            var killed = TerminateProcmon(repoRoot);
            return new RecordingStopItemDto("procmon", null, killed ? "terminated" : "not running");
        }, items);

        Safe("debugview", () =>
        {
            var n = KillProcessesByName("Dbgview", "dbgview", "Dbgview64");
            return new RecordingStopItemDto("debugview", null, n > 0 ? $"killed {n}" : "not running");
        }, items);

        Safe("procdump", () =>
        {
            var n = KillProcessesByName("procdump", "procdump64");
            return new RecordingStopItemDto("procdump", null, n > 0 ? $"killed {n}" : "not running");
        }, items);

        Safe("etw", () =>
        {
            var ok = CancelWpr();
            return new RecordingStopItemDto("etw", null, ok ? "wpr -cancel" : "wpr unavailable");
        }, items);

        Safe("pktmon", () =>
        {
            var ok = StopPktmon();
            return new RecordingStopItemDto("pktmon", null, ok ? "pktmon stop" : "pktmon unavailable");
        }, items);

        Safe("tshark", () =>
        {
            var ok = TsharkCapture.StopHostCaptures();
            return new RecordingStopItemDto("tshark", null, ok ? "tshark/dumpcap killed" : "not running");
        }, items);

        var message = FormatSummary(items);
        return new RecordingStopResultDto(true, message, items);
    }

    private static void Safe(string name, Func<RecordingStopItemDto?> action, List<RecordingStopItemDto> items)
    {
        try
        {
            var item = action();
            if (item is not null)
                items.Add(item);
        }
        catch (Exception ex)
        {
            items.Add(new RecordingStopItemDto(name, null, $"error: {ex.Message}"));
        }
    }

    private static string FormatSummary(IReadOnlyList<RecordingStopItemDto> items)
    {
        if (items.Count == 0)
            return "Recording stopped: (nothing to stop)";

        var sb = new StringBuilder("Recording stopped: ");
        for (var i = 0; i < items.Count; i++)
        {
            if (i > 0) sb.Append(", ");
            var it = items[i];
            sb.Append(it.Name);
            if (!string.IsNullOrWhiteSpace(it.Path))
                sb.Append(" → ").Append(it.Path);
            else if (!string.IsNullOrWhiteSpace(it.Status))
                sb.Append(" (").Append(it.Status).Append(')');
        }

        return sb.ToString();
    }

    private static bool TerminateProcmon(string? repoRoot)
    {
        var exe = ProcmonCapture.DiscoverExecutable(repoRoot);
        var terminated = false;
        if (exe is not null)
        {
            try
            {
                using var p = Process.Start(new ProcessStartInfo
                {
                    FileName = exe,
                    Arguments = "/Terminate /Quiet /AcceptEula",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                });
                p?.WaitForExit(8000);
                terminated = true;
            }
            catch
            {
                /* fall through to Kill */
            }
        }

        var n = KillProcessesByName("Procmon64", "Procmon", "procmon");
        return terminated || n > 0;
    }

    private static int KillProcessesByName(params string[] names)
    {
        if (!OperatingSystem.IsWindows())
            return 0;

        var count = 0;
        foreach (var name in names)
        {
            Process[] procs;
            try { procs = Process.GetProcessesByName(name); }
            catch { continue; }

            foreach (var p in procs)
            {
                try
                {
                    if (!p.HasExited)
                    {
                        p.Kill(entireProcessTree: true);
                        p.WaitForExit(5000);
                        count++;
                    }
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

        return count;
    }

    private static bool CancelWpr()
    {
        var exe = EtwCapture.DiscoverExecutable();
        if (exe is null)
            return false;
        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = exe,
                Arguments = "-cancel",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            proc?.WaitForExit(15_000);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool StopPktmon()
    {
        var exe = PktmonCapture.DiscoverExecutable();
        if (exe is null)
            return false;
        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = exe,
                Arguments = "stop",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            proc?.WaitForExit(30_000);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
