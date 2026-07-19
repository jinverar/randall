using System.Diagnostics;
using System.Text;

namespace Randall.Infrastructure;

/// <summary>
/// Opt-in Sysinternals snapshot bundle: Handle, ListDLLs, PsList (and netstat network snapshot —
/// TCPView has no useful CLI). Captures at arm / disarm / crash under the run journal.
/// Soft-fails per tool when binaries are missing.
/// </summary>
public sealed class SysinternalsSnapshots : IDisposable
{
    private bool _disposed;
    private readonly List<string> _warnings = [];

    public string SnapshotDir { get; }
    public string MetaPath { get; }
    public bool AnyToolFound { get; }
    public string? HandlePath { get; }
    public string? ListDllsPath { get; }
    public string? PsListPath { get; }
    public string? PsInfoPath { get; }
    public IReadOnlyList<string> Warnings => _warnings;
    public string? LastError => _warnings.Count > 0 ? string.Join("; ", _warnings) : null;

    private SysinternalsSnapshots(
        string snapshotDir,
        string metaPath,
        string? handlePath,
        string? listDllsPath,
        string? psListPath,
        string? psInfoPath)
    {
        SnapshotDir = snapshotDir;
        MetaPath = metaPath;
        HandlePath = handlePath;
        ListDllsPath = listDllsPath;
        PsListPath = psListPath;
        PsInfoPath = psInfoPath;
        AnyToolFound = handlePath is not null || listDllsPath is not null ||
                       psListPath is not null || psInfoPath is not null;
    }

    public static SysinternalsSnapshots TryBegin(string runDirectory, string? repoRoot = null)
    {
        Directory.CreateDirectory(runDirectory);
        var dir = Path.Combine(runDirectory, "sysinternals");
        Directory.CreateDirectory(dir);
        var meta = Path.Combine(dir, "snapshots.txt");

        var snap = new SysinternalsSnapshots(
            dir,
            meta,
            SysinternalsToolPaths.FindHandle(repoRoot),
            SysinternalsToolPaths.FindListDlls(repoRoot),
            SysinternalsToolPaths.FindPsList(repoRoot),
            SysinternalsToolPaths.FindPsInfo(repoRoot));

        if (!OperatingSystem.IsWindows())
        {
            snap._warnings.Add("Sysinternals snapshots are Windows-only");
            WriteMeta(snap, "skipped — not Windows");
            return snap;
        }

        if (!snap.AnyToolFound)
        {
            snap._warnings.Add(
                "No Handle/ListDLLs/PsList found (tools/ or PATH) — copy from Sysinternals Suite");
            WriteMeta(snap, "skipped — no tools");
            return snap;
        }

        WriteMeta(snap, "armed");
        return snap;
    }

    /// <summary>Bookend at target start (after PID is known).</summary>
    public void CaptureArm(int? pid) => Capture("arm", pid);

    /// <summary>Bookend at run stop.</summary>
    public void CaptureDisarm(int? pid) => Capture("disarm", pid);

    /// <summary>On-crash snapshot (best-effort; process may already be gone).</summary>
    public void CaptureCrash(int? pid) => Capture($"crash_{DateTime.UtcNow:yyyyMMdd_HHmmss}", pid);

    public void Capture(string label, int? pid)
    {
        if (!OperatingSystem.IsWindows() || _disposed)
            return;

        var safe = SanitizeLabel(label);
        var wrote = 0;

        if (pid is > 0)
        {
            if (HandlePath is not null &&
                RunTool(HandlePath, $"-accepteula -p {pid.Value}", Path.Combine(SnapshotDir, $"{safe}-handle.txt")))
                wrote++;

            if (ListDllsPath is not null &&
                RunTool(ListDllsPath, $"-accepteula {pid.Value}", Path.Combine(SnapshotDir, $"{safe}-listdlls.txt")))
                wrote++;

            if (PsListPath is not null &&
                RunTool(PsListPath, $"-accepteula {pid.Value}", Path.Combine(SnapshotDir, $"{safe}-pslist.txt")))
                wrote++;
        }
        else
        {
            // No PID yet — still take a host-wide process list if available.
            if (PsListPath is not null &&
                RunTool(PsListPath, "-accepteula", Path.Combine(SnapshotDir, $"{safe}-pslist.txt")))
                wrote++;
        }

        // Network snapshot (TCPView is GUI-only; netstat is the automatable stand-in).
        if (CaptureNetstat(Path.Combine(SnapshotDir, $"{safe}-netstat.txt")))
            wrote++;

        // Optional one-shot host info (light).
        if (string.Equals(safe, "arm", StringComparison.OrdinalIgnoreCase) &&
            PsInfoPath is not null &&
            RunTool(PsInfoPath, "-accepteula", Path.Combine(SnapshotDir, $"{safe}-psinfo.txt")))
            wrote++;

        try
        {
            File.AppendAllText(MetaPath,
                $"{DateTimeOffset.UtcNow:O} {safe} pid={(pid?.ToString() ?? "none")} files={wrote}\n");
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
                _warnings.Add($"failed to start {Path.GetFileName(exe)}");
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
            _warnings.Add($"{Path.GetFileName(exe)}: {ex.Message}");
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

    private static bool CaptureNetstat(string outPath)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netstat.exe",
                Arguments = "-ano",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var proc = Process.Start(psi);
            if (proc is null) return false;
            var stdout = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(15_000);
            File.WriteAllText(outPath,
                $"# netstat -ano (TCPView has no useful CLI — network snapshot stand-in)\n" +
                $"# utc={DateTimeOffset.UtcNow:O}\n" +
                stdout);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void WriteMeta(SysinternalsSnapshots snap, string status)
    {
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Sysinternals snapshots: {status}");
            sb.AppendLine($"Dir: {snap.SnapshotDir}");
            sb.AppendLine($"Handle: {snap.HandlePath ?? "(missing)"}");
            sb.AppendLine($"ListDLLs: {snap.ListDllsPath ?? "(missing)"}");
            sb.AppendLine($"PsList: {snap.PsListPath ?? "(missing)"}");
            sb.AppendLine($"PsInfo: {snap.PsInfoPath ?? "(optional, missing)"}");
            sb.AppendLine("TCPView: skipped (GUI-only) — netstat -ano used instead");
            sb.AppendLine("VMMap: skipped (GUI-only / no stable CLI bookend)");
            sb.AppendLine("Bundle: handle + listdlls + pslist at arm/disarm/crash; netstat each time; psinfo on arm");
            if (snap._warnings.Count > 0)
            {
                sb.AppendLine("Warnings:");
                foreach (var w in snap._warnings)
                    sb.AppendLine($"  - {w}");
            }

            File.WriteAllText(snap.MetaPath, sb.ToString());
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
