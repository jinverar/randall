using System.Diagnostics;
using System.Text;

namespace Randall.Infrastructure;

/// <summary>
/// Sysinternals TCPVCon bookends — network connection snapshots at arm / disarm / crash
/// (CLI companion to TCPView). Soft-fails when tcpvcon/tcpvcon64 is missing.
/// </summary>
public sealed class TcpvconCapture : IDisposable
{
    private bool _disposed;
    private readonly List<string> _warnings = [];

    public string CaptureDir { get; }
    public string MetaPath { get; }
    public string? ExecutablePath { get; }
    public bool Available => ExecutablePath is not null && OperatingSystem.IsWindows();
    public IReadOnlyList<string> Warnings => _warnings;
    public string? LastError => _warnings.Count > 0 ? string.Join("; ", _warnings) : null;

    private TcpvconCapture(string captureDir, string metaPath, string? executablePath)
    {
        CaptureDir = captureDir;
        MetaPath = metaPath;
        ExecutablePath = executablePath;
    }

    public static string? DiscoverExecutable(string? repoRoot = null) =>
        SysinternalsToolPaths.FindTcpvcon(repoRoot);

    /// <summary>
    /// Arm capture for a run directory. Returns an object even when TCPVCon is missing
    /// so callers can warn without failing the campaign.
    /// </summary>
    public static TcpvconCapture TryBegin(string runDirectory, string? repoRoot = null)
    {
        Directory.CreateDirectory(runDirectory);
        var dir = Path.Combine(runDirectory, "tcpvcon");
        Directory.CreateDirectory(dir);
        var meta = Path.Combine(runDirectory, "tcpvcon-capture.txt");
        var exe = DiscoverExecutable(repoRoot);

        var capture = new TcpvconCapture(dir, meta, exe);

        if (!OperatingSystem.IsWindows())
        {
            capture._warnings.Add("TCPVCon capture is Windows-only");
            WriteMeta(capture, "skipped — not Windows");
            return capture;
        }

        if (exe is null)
        {
            capture._warnings.Add(
                "tcpvcon/tcpvcon64 not found (tools/ or PATH) — copy from Sysinternals TCPView package");
            WriteMeta(capture, "skipped — TCPVCon not found");
            return capture;
        }

        WriteMeta(capture, "armed");
        return capture;
    }

    /// <summary>Bookend at target start (after PID is known).</summary>
    public void CaptureArm(int? pid) => Capture("arm", pid);

    /// <summary>Bookend at run stop.</summary>
    public void CaptureDisarm(int? pid) => Capture("disarm", pid);

    /// <summary>On-crash snapshot (best-effort; process may already be gone).</summary>
    public void CaptureCrash(int? pid) => Capture($"crash_{DateTime.UtcNow:yyyyMMdd_HHmmss}", pid);

    public void Capture(string label, int? pid)
    {
        if (!Available || _disposed)
            return;

        var safe = SanitizeLabel(label);
        var outPath = Path.Combine(CaptureDir, $"{safe}.txt");
        // -a all endpoints · -c CSV · -n numeric (no DNS) · optional PID filter
        var args = pid is > 0
            ? $"-accepteula -a -c -n {pid.Value}"
            : "-accepteula -a -c -n";

        if (RunTool(ExecutablePath!, args, outPath))
        {
            try
            {
                File.AppendAllText(MetaPath,
                    $"{DateTimeOffset.UtcNow:O} {safe} pid={(pid?.ToString() ?? "all")} → {outPath}\n");
            }
            catch
            {
                /* ignore */
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
    }

    private bool RunTool(string exe, string args, string outPath)
    {
        try
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
            using var proc = Process.Start(psi);
            if (proc is null)
            {
                _warnings.Add("failed to start TCPVCon");
                return false;
            }

            var stdout = proc.StandardOutput.ReadToEnd();
            var stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit(30_000);
            var body = new StringBuilder();
            body.AppendLine($"# {Path.GetFileName(exe)} {args}");
            body.AppendLine($"# exit={proc.ExitCode} utc={DateTimeOffset.UtcNow:O}");
            if (!string.IsNullOrWhiteSpace(stderr))
                body.AppendLine($"# stderr: {stderr.Trim()}");
            body.AppendLine(stdout);
            File.WriteAllText(outPath, body.ToString());
            return true;
        }
        catch (Exception ex)
        {
            _warnings.Add(ex.Message);
            try
            {
                File.WriteAllText(outPath, $"# error: {ex.Message}\n");
            }
            catch
            {
                /* ignore */
            }

            return false;
        }
    }

    private static void WriteMeta(TcpvconCapture capture, string status)
    {
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine($"TCPVCon capture: {status}");
            sb.AppendLine($"Executable: {capture.ExecutablePath ?? "(missing)"}");
            sb.AppendLine($"Dir: {capture.CaptureDir}");
            sb.AppendLine("Snapshots at arm / disarm / crash (all endpoints, CSV, numeric addresses).");
            sb.AppendLine("From Sysinternals TCPView package — tcpvcon64.exe / tcpvcon.exe.");
            if (capture._warnings.Count > 0)
            {
                sb.AppendLine("Warnings:");
                foreach (var w in capture._warnings)
                    sb.AppendLine($"  - {w}");
            }

            File.WriteAllText(capture.MetaPath, sb.ToString());
        }
        catch
        {
            /* ignore */
        }
    }

    private static string SanitizeLabel(string label)
    {
        var chars = label.Trim().ToLowerInvariant().Select(c =>
            char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_').ToArray();
        var s = new string(chars);
        return string.IsNullOrWhiteSpace(s) ? "snap" : s;
    }
}
