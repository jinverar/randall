using System.Diagnostics;
using System.Text.Json;

namespace Randall.Infrastructure;

/// <summary>
/// Linux counterpart to <see cref="MiniDumpWriter"/> — collect kernel core dumps (and optional
/// <c>gcore</c> snapshots) into the crash dumps directory for triage with gdb/GEF.
/// </summary>
public static class LinuxCoreCapture
{
    /// <summary>
    /// Best-effort core capture for a crashed or crashing process. Returns the path to a copied
    /// <c>.core</c> file under <paramref name="dumpsDir"/>, or null if none was found.
    /// Always writes a small <c>.linux.json</c> sidecar with exit/signal metadata when possible.
    /// </summary>
    public static string? TryCapture(
        Process process,
        string dumpsDir,
        string baseName)
    {
        if (!OperatingSystem.IsLinux())
            return null;

        try
        {
            Directory.CreateDirectory(dumpsDir);

            int pid;
            string? exeName = null;
            int? exitCode = null;
            try { pid = process.Id; }
            catch { return null; }

            try
            {
                exeName = Path.GetFileName(process.MainModule?.FileName)
                          ?? process.ProcessName;
            }
            catch
            {
                try { exeName = process.ProcessName; }
                catch { /* ignore */ }
            }

            try
            {
                if (process.HasExited)
                    exitCode = process.ExitCode;
            }
            catch { /* ignore */ }

            string? corePath = null;

            // Live process: try gcore (gdb) before it disappears.
            if (!process.HasExited)
                corePath = TryGcore(pid, dumpsDir, baseName);

            // Kernel cores (core_pattern like /tmp/core.%e.%p) — preferred after SIGSEGV etc.
            corePath ??= FindKernelCore(pid, exeName);

            string? destCore = null;
            if (corePath is not null && File.Exists(corePath))
            {
                destCore = Path.Combine(dumpsDir, $"{baseName}.core");
                try
                {
                    File.Copy(corePath, destCore, overwrite: true);
                }
                catch
                {
                    destCore = null;
                }
            }

            WriteSidecar(dumpsDir, baseName, pid, exeName, exitCode, corePath, destCore);
            return destCore;
        }
        catch
        {
            return null;
        }
    }

    private static string? TryGcore(int pid, string dumpsDir, string baseName)
    {
        // gcore ships with gdb; optional — kernel cores cover the common SIGSEGV path.
        var gcore = Environment.GetEnvironmentVariable("GCORE_PATH");
        if (string.IsNullOrWhiteSpace(gcore) || !File.Exists(gcore))
            gcore = FindOnPath("gcore");
        if (gcore is null)
            return null;

        var outPrefix = Path.Combine(dumpsDir, baseName);
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = gcore,
                Arguments = $"-o \"{outPrefix}\" {pid}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi);
            if (proc is null)
                return null;
            if (!proc.WaitForExit(15_000))
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* ignore */ }
                return null;
            }

            // gcore writes <prefix>.<pid>
            var candidate = $"{outPrefix}.{pid}";
            if (File.Exists(candidate) && new FileInfo(candidate).Length > 0)
                return candidate;

            return Directory.EnumerateFiles(dumpsDir, $"{baseName}.*")
                .Where(f => !f.EndsWith(".linux.json", StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(f => new FileInfo(f).LastWriteTimeUtc)
                .FirstOrDefault(f => new FileInfo(f).Length > 0);
        }
        catch
        {
            return null;
        }
    }

    private static string? FindKernelCore(int pid, string? exeName)
    {
        var candidates = new List<string>();

        // Match common patterns from core_pattern.
        if (!string.IsNullOrWhiteSpace(exeName))
        {
            candidates.Add(Path.Combine("/tmp", $"core.{exeName}.{pid}"));
            candidates.Add(Path.Combine("/var/lib/systemd/coredump", $"core.{exeName}.{pid}"));
        }

        candidates.Add(Path.Combine("/tmp", $"core.{pid}"));
        candidates.Add($"core.{pid}");
        candidates.Add("core");

        foreach (var c in candidates)
        {
            if (File.Exists(c) && new FileInfo(c).Length > 0)
                return Path.GetFullPath(c);
        }

        // Recent /tmp/core.* for this exe (pid may be in the name).
        try
        {
            var cutoff = DateTime.UtcNow - TimeSpan.FromMinutes(2);
            IEnumerable<string> recent = Directory.Exists("/tmp")
                ? Directory.EnumerateFiles("/tmp", "core.*")
                : [];
            if (!string.IsNullOrWhiteSpace(exeName))
            {
                recent = recent.Where(f =>
                    Path.GetFileName(f).Contains(exeName, StringComparison.OrdinalIgnoreCase)
                    || Path.GetFileName(f).EndsWith($".{pid}", StringComparison.Ordinal));
            }
            else
            {
                recent = recent.Where(f =>
                    Path.GetFileName(f).EndsWith($".{pid}", StringComparison.Ordinal));
            }

            return recent
                .Select(f => new FileInfo(f))
                .Where(f => f.Exists && f.Length > 0 && f.LastWriteTimeUtc >= cutoff)
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .Select(f => f.FullName)
                .FirstOrDefault();
        }
        catch
        {
            return null;
        }
    }

    private static void WriteSidecar(
        string dumpsDir,
        string baseName,
        int pid,
        string? exeName,
        int? exitCode,
        string? sourceCore,
        string? destCore)
    {
        int? signal = null;
        string? signalName = null;
        if (exitCode is >= 129 and <= 159)
        {
            signal = exitCode.Value - 128;
            signalName = signal.Value switch
            {
                4 => "SIGILL",
                6 => "SIGABRT",
                7 => "SIGBUS",
                8 => "SIGFPE",
                11 => "SIGSEGV",
                _ => $"signal {signal}",
            };
        }

        var path = Path.Combine(dumpsDir, $"{baseName}.linux.json");
        var payload = new
        {
            pid,
            exeName,
            exitCode,
            signal,
            signalName,
            sourceCore,
            corePath = destCore,
            capturedAtUtc = DateTimeOffset.UtcNow,
            note = destCore is null
                ? "No core file found. Ensure ulimit -c unlimited and a file core_pattern (e.g. /tmp/core.%e.%p)."
                : "Core captured for gdb/GEF triage (randall heaptriage / exploit guide).",
        };
        try
        {
            File.WriteAllText(path, JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { /* ignore */ }
    }

    private static string? FindOnPath(string name)
    {
        var path = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(dir, name);
            if (File.Exists(candidate))
                return candidate;
        }

        return null;
    }
}
