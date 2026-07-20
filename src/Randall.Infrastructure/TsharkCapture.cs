using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace Randall.Infrastructure;

/// <summary>
/// Wireshark <c>tshark</c> bookend — live NIC capture to pcapng under the run journal.
/// Soft-fails when tshark/Npcap is missing or capture is denied (often needs Npcap + admin).
/// </summary>
public sealed class TsharkCapture : IDisposable
{
    private Process? _process;
    private bool _disposed;
    private bool _stopped;

    public string PcapPath { get; }
    public string MetaPath { get; }
    public string? ExecutablePath { get; }
    public string? Interface { get; private set; }
    public string? CaptureFilter { get; private set; }
    public bool IsRunning => _process is { HasExited: false };
    public string? LastError { get; private set; }

    private TsharkCapture(string pcapPath, string metaPath, string? executablePath)
    {
        PcapPath = pcapPath;
        MetaPath = metaPath;
        ExecutablePath = executablePath;
    }

    public static string? DiscoverExecutable(string? repoRoot = null)
    {
        if (!OperatingSystem.IsWindows())
        {
            // Still allow PATH discovery on non-Windows for doctor/docs parity.
        }

        var fromEnv = Environment.GetEnvironmentVariable("TSHARK_PATH");
        if (!string.IsNullOrWhiteSpace(fromEnv) && File.Exists(fromEnv))
            return fromEnv;

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        foreach (var name in new[] { "tshark.exe", "tshark" })
        {
            var inTools = Path.Combine(repoRoot, "tools", name);
            if (File.Exists(inTools))
                return inTools;
        }

        var fromPath = FindOnPath("tshark.exe") ?? FindOnPath("tshark");
        if (fromPath is not null)
            return fromPath;

        foreach (var candidate in new[]
                 {
                     Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                         "Wireshark", "tshark.exe"),
                     Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                         "Wireshark", "tshark.exe"),
                     @"C:\Program Files\Wireshark\tshark.exe",
                     @"C:\Program Files (x86)\Wireshark\tshark.exe",
                 })
        {
            if (File.Exists(candidate))
                return candidate;
        }

        return null;
    }

    /// <summary>
    /// Optional BPF filter from project transport (host/port). Null → capture all on chosen iface.
    /// </summary>
    public static string? BuildCaptureFilter(string? host, int port)
    {
        if (port is <= 0 or > 65535)
            return null;

        if (string.IsNullOrWhiteSpace(host))
            return $"port {port}";

        var h = host.Trim();
        // BPF host keyword accepts IPv4/IPv6/name; keep simple for lab localhost targets.
        return $"host {h} and port {port}";
    }

    /// <summary>
    /// Start tshark writing <c>fuzz.pcapng</c>. Returns an object even when missing so callers can warn.
    /// </summary>
    public static TsharkCapture TryStart(
        string runDirectory,
        string? host = null,
        int port = 0,
        string? repoRoot = null)
    {
        Directory.CreateDirectory(runDirectory);
        var pcap = Path.Combine(runDirectory, "fuzz.pcapng");
        var meta = Path.Combine(runDirectory, "tshark-capture.txt");
        var exe = DiscoverExecutable(repoRoot);

        if (exe is null)
        {
            var missing = new TsharkCapture(pcap, meta, null)
            {
                LastError =
                    "tshark.exe not found — install Wireshark (includes tshark + Npcap), " +
                    "or: winget install WiresharkFoundation.Wireshark / choco install wireshark " +
                    "(or place tshark.exe in tools/ / PATH / TSHARK_PATH)",
            };
            TryWriteMeta(missing, "skipped — tshark not found");
            return missing;
        }

        // Best-effort: stop prior capture so the pcap path is free.
        try
        {
            KillTsharkTree();
        }
        catch
        {
            /* ignore */
        }

        if (File.Exists(pcap))
        {
            try { File.Delete(pcap); }
            catch { /* ignore */ }
        }

        var capture = new TsharkCapture(pcap, meta, exe)
        {
            CaptureFilter = BuildCaptureFilter(host, port),
        };

        var iface = PickInterface(exe);
        capture.Interface = iface ?? "1";

        try
        {
            var args = new StringBuilder();
            args.Append("-i ").Append(QuoteArg(capture.Interface));
            args.Append(" -w ").Append(QuoteArg(pcap));
            args.Append(" -q"); // quieter; still needs dumpcap/Npcap rights
            if (!string.IsNullOrWhiteSpace(capture.CaptureFilter))
                args.Append(" -f ").Append(QuoteArg(capture.CaptureFilter));

            capture._process = Process.Start(new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args.ToString(),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });

            if (capture._process is null)
            {
                capture.LastError = "failed to start tshark";
                TryWriteMeta(capture, "start failed");
                return capture;
            }

            // Early-exit detection (missing Npcap / access denied / bad interface).
            Thread.Sleep(800);
            if (capture._process.HasExited)
            {
                var stderr = "";
                var stdout = "";
                try { stderr = capture._process.StandardError.ReadToEnd(); } catch { /* ignore */ }
                try { stdout = capture._process.StandardOutput.ReadToEnd(); } catch { /* ignore */ }
                var detail = string.IsNullOrWhiteSpace(stderr) ? stdout.Trim() : stderr.Trim();
                capture.LastError = string.IsNullOrWhiteSpace(detail)
                    ? $"tshark exited immediately (code {capture._process.ExitCode})"
                    : detail;
                if (LooksLikePrivilegeError(capture.LastError, capture._process.ExitCode))
                {
                    capture.LastError +=
                        " (Npcap/admin often required — try elevated console/agent, or reinstall Npcap with WinPcap API compat)";
                }

                capture._process.Dispose();
                capture._process = null;
                TryWriteMeta(capture, "start failed");
                return capture;
            }

            // Drain pipes so buffers cannot fill during a long run.
            _ = Task.Run(() =>
            {
                try { capture._process?.StandardOutput.ReadToEnd(); } catch { /* ignore */ }
            });
            _ = Task.Run(() =>
            {
                try { capture._process?.StandardError.ReadToEnd(); } catch { /* ignore */ }
            });

            TryWriteMeta(capture, "running");
        }
        catch (Exception ex)
        {
            capture.LastError = ex.Message;
            if (LooksLikePrivilegeError(ex.Message, null))
            {
                capture.LastError +=
                    " (Npcap/admin often required — try elevated console/agent)";
            }

            TryWriteMeta(capture, "start exception");
        }

        return capture;
    }

    public void Stop()
    {
        if (_stopped) return;
        _stopped = true;

        if (_process is null)
        {
            TryWriteMeta(this, File.Exists(PcapPath) ? "stopped — pcap present" : "stopped");
            return;
        }

        try
        {
            if (!_process.HasExited)
            {
                // Kill tree so child dumpcap.exe stops too (Windows tshark → dumpcap).
                _process.Kill(entireProcessTree: true);
                _process.WaitForExit(15_000);
            }
        }
        catch (Exception ex)
        {
            LastError ??= ex.Message;
        }
        finally
        {
            try { _process.Dispose(); } catch { /* ignore */ }
            _process = null;
        }

        // Orphan dumpcap left by a half-dead tree.
        try { KillProcessesByName("dumpcap"); } catch { /* ignore */ }

        TryWriteMeta(this, File.Exists(PcapPath) && new FileInfo(PcapPath).Length > 0
            ? "stopped — pcapng saved"
            : "stopped — empty or missing pcap (capture may need Npcap/admin)");
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (IsRunning || !_stopped)
            Stop();
    }

    /// <summary>Host-wide emergency stop for orphaned tshark/dumpcap.</summary>
    public static bool StopHostCaptures()
    {
        var n = KillTsharkTree();
        return n > 0;
    }

    private static int KillTsharkTree()
    {
        var n = KillProcessesByName("tshark");
        n += KillProcessesByName("dumpcap");
        return n;
    }

    private static string? PickInterface(string exe)
    {
        try
        {
            var (code, stdout, _) = Run(exe, "-D", waitMs: 12_000);
            if (code != 0 || string.IsNullOrWhiteSpace(stdout))
                return "1";

            string? fallback = null;
            foreach (var raw in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                // "1. \Device\NPF_{…} (Ethernet)" or "1. eth0"
                var m = Regex.Match(raw, @"^(\d+)\.\s+(.+)$");
                if (!m.Success) continue;

                var index = m.Groups[1].Value;
                var rest = m.Groups[2].Value;
                fallback ??= index;

                if (rest.Contains("loopback", StringComparison.OrdinalIgnoreCase) ||
                    rest.Contains("Npcap Loopback", StringComparison.OrdinalIgnoreCase))
                    continue;

                return index;
            }

            return fallback ?? "1";
        }
        catch
        {
            return "1";
        }
    }

    private static (int ExitCode, string Stdout, string Stderr) Run(string exe, string args, int waitMs)
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
        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("failed to start tshark");
        var stdout = proc.StandardOutput.ReadToEnd();
        var stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit(waitMs);
        return (proc.ExitCode, stdout, stderr);
    }

    private static void TryWriteMeta(TsharkCapture capture, string status)
    {
        try
        {
            File.WriteAllText(capture.MetaPath,
                $"tshark capture: {status}\n" +
                $"Executable: {capture.ExecutablePath ?? "(missing)"}\n" +
                $"Interface: {capture.Interface ?? "(n/a)"}\n" +
                $"Filter: {capture.CaptureFilter ?? "(none — all traffic on iface)"}\n" +
                $"PCAP: {capture.PcapPath}\n" +
                (capture.LastError is not null ? $"Error: {capture.LastError}\n" : "") +
                "Install: Wireshark (winget install WiresharkFoundation.Wireshark) — needs Npcap; capture often requires elevation.\n" +
                "Open in Wireshark: File → Open → fuzz.pcapng\n");
        }
        catch
        {
            /* ignore */
        }
    }

    private static bool LooksLikePrivilegeError(string? text, int? exitCode)
    {
        if (exitCode is 5 or 1)
            return true;
        if (string.IsNullOrWhiteSpace(text))
            return false;
        return text.Contains("access", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("denied", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("elevat", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("privilege", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("Npcap", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("permission", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("not permitted", StringComparison.OrdinalIgnoreCase);
    }

    private static string QuoteArg(string value) =>
        value.Contains(' ') || value.Contains('"')
            ? "\"" + value.Replace("\"", "\\\"") + "\""
            : value;

    private static string? FindOnPath(string fileName)
    {
        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathEnv.Split(Path.PathSeparator))
        {
            if (string.IsNullOrWhiteSpace(dir)) continue;
            var candidate = Path.Combine(dir.Trim('"'), fileName);
            if (File.Exists(candidate))
                return candidate;
        }

        return null;
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
}
