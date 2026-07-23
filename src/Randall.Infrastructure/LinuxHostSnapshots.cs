using System.Diagnostics;
using System.Text;

namespace Randall.Infrastructure;

/// <summary>
/// Linux twin of SysinternalsSnapshots for baseline / Exploit Surface:
/// <c>ss</c> listen table, <c>/proc/&lt;pid&gt;/maps</c>, optional <c>ldd</c> on the target exe.
/// Soft-fails per probe. Artifacts land under <c>data/runs/…/linux/</c>.
/// </summary>
public sealed class LinuxHostSnapshots : IDisposable
{
    private bool _disposed;
    private readonly List<string> _warnings = [];
    private bool _lddDone;

    public string SnapshotDir { get; }
    public string MetaPath { get; }
    public bool AnyProbeAvailable { get; }
    public IReadOnlyList<string> Warnings => _warnings;
    public string? LastError => _warnings.Count > 0 ? string.Join("; ", _warnings) : null;

    private LinuxHostSnapshots(string snapshotDir, string metaPath, bool anyProbe)
    {
        SnapshotDir = snapshotDir;
        MetaPath = metaPath;
        AnyProbeAvailable = anyProbe;
    }

    public static LinuxHostSnapshots TryBegin(string runDirectory)
    {
        Directory.CreateDirectory(runDirectory);
        var dir = Path.Combine(runDirectory, "linux");
        Directory.CreateDirectory(dir);
        var meta = Path.Combine(dir, "snapshots.txt");
        var any = OperatingSystem.IsLinux() && (File.Exists("/bin/ss") || File.Exists("/usr/bin/ss")
                                                || Directory.Exists("/proc"));
        var snap = new LinuxHostSnapshots(dir, meta, any);
        if (!OperatingSystem.IsLinux())
        {
            snap._warnings.Add("Linux host snapshots are Linux-only");
            WriteMeta(snap, "skipped — not Linux");
            return snap;
        }

        WriteMeta(snap, any ? "armed" : "skipped — no ss/proc");
        return snap;
    }

    public void CaptureArm(int? pid, string? targetExecutable = null) =>
        Capture("arm", pid, targetExecutable);

    public void CaptureDisarm(int? pid) => Capture("disarm", pid);

    public void Capture(string label, int? pid, string? targetExecutable = null)
    {
        if (!OperatingSystem.IsLinux() || _disposed)
            return;

        var safe = SanitizeLabel(label);
        var wrote = 0;
        var isArm = string.Equals(safe, "arm", StringComparison.OrdinalIgnoreCase);

        if (CaptureSs(Path.Combine(SnapshotDir, $"{safe}-ss.txt")))
            wrote++;

        if (pid is > 0)
        {
            if (CaptureProcFile(pid.Value, "maps", Path.Combine(SnapshotDir, $"{safe}-maps.txt")))
                wrote++;
            if (CaptureProcFile(pid.Value, "cmdline", Path.Combine(SnapshotDir, $"{safe}-cmdline.txt"),
                    transform: b => b.Replace('\0', ' ').Trim()))
                wrote++;
            if (CaptureProcFile(pid.Value, "status", Path.Combine(SnapshotDir, $"{safe}-status.txt")))
                wrote++;
        }

        if (isArm && !_lddDone && !string.IsNullOrWhiteSpace(targetExecutable) && File.Exists(targetExecutable))
        {
            _lddDone = true;
            if (RunTool("ldd", Quote(targetExecutable!), Path.Combine(SnapshotDir, "ldd-target.txt")))
                wrote++;
        }

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

    private bool CaptureSs(string outPath)
    {
        // Prefer ss -ltnup; fall back to ss -ltn then netstat.
        if (RunTool("ss", "-ltnup", outPath) || RunTool("ss", "-ltn", outPath))
            return true;
        if (RunTool("netstat", "-ltnp", outPath))
            return true;
        _warnings.Add("ss/netstat listen snapshot failed");
        return false;
    }

    private bool CaptureProcFile(int pid, string name, string outPath, Func<string, string>? transform = null)
    {
        try
        {
            var src = $"/proc/{pid}/{name}";
            if (!File.Exists(src))
            {
                _warnings.Add($"missing {src}");
                return false;
            }

            var body = File.ReadAllText(src);
            if (transform is not null)
                body = transform(body);
            File.WriteAllText(outPath,
                $"# /proc/{pid}/{name}\n# utc={DateTimeOffset.UtcNow:O}\n{body}");
            return true;
        }
        catch (Exception ex)
        {
            _warnings.Add($"/proc/{pid}/{name}: {ex.Message}");
            return false;
        }
    }

    private bool RunTool(string exe, string args, string outPath, int timeoutMs = 15_000)
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
                _warnings.Add($"failed to start {exe}");
                return false;
            }

            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();
            if (!proc.WaitForExit(timeoutMs))
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* */ }
                _warnings.Add($"{exe} timed out");
                return false;
            }

            var stdout = stdoutTask.GetAwaiter().GetResult();
            var stderr = stderrTask.GetAwaiter().GetResult();
            var sb = new StringBuilder();
            sb.AppendLine($"# {exe} {args}");
            sb.AppendLine($"# exit={proc.ExitCode} utc={DateTimeOffset.UtcNow:O}");
            if (!string.IsNullOrWhiteSpace(stderr))
                sb.AppendLine($"# stderr: {stderr.Trim()}");
            sb.AppendLine(stdout);
            File.WriteAllText(outPath, sb.ToString());
            return proc.ExitCode == 0 || stdout.Length > 0;
        }
        catch (Exception ex)
        {
            _warnings.Add($"{exe}: {ex.Message}");
            return false;
        }
    }

    private static string Quote(string path) =>
        path.Contains(' ') ? $"\"{path}\"" : path;

    private static void WriteMeta(LinuxHostSnapshots snap, string status)
    {
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Linux host snapshots: {status}");
            sb.AppendLine($"Dir: {snap.SnapshotDir}");
            sb.AppendLine("Probes: ss -ltnup · /proc/<pid>/maps · /proc/<pid>/cmdline · ldd (arm)");
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
