using System.Diagnostics;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Launch WinDbg / WinDbg Preview / cdb / ProcDump for attach, wait-for-crash, and dump open.
/// Research triage only — no exploit automation.
/// </summary>
public static class DebuggerSession
{
    public static DebuggerLaunchResultDto OpenDump(string dumpPath, string kind = DebuggerTools.KindAuto)
    {
        dumpPath = Path.GetFullPath(dumpPath);
        if (!File.Exists(dumpPath))
            return Fail(kind, $"Dump not found: {dumpPath}");

        var resolvedKind = DebuggerTools.ResolveGuiKind(kind);
        var exe = DebuggerTools.ResolveGuiPath(resolvedKind);
        if (exe is null)
            return Fail(resolvedKind, "No WinDbg / WinDbg Preview / cdb found. Install Debugging Tools for Windows or WinDbg Preview.");

        var args = $"-z \"{dumpPath}\"";
        try
        {
            var gui = resolvedKind is not DebuggerTools.KindCdb;
            var proc = Process.Start(DebuggerTools.BuildStartInfo(exe, args, gui));
            return new DebuggerLaunchResultDto(
                true, resolvedKind, exe, proc?.Id, dumpPath,
                $"Opened dump in {resolvedKind}: {dumpPath}");
        }
        catch (Exception ex)
        {
            return Fail(resolvedKind, ex.Message, exe, dumpPath);
        }
    }

    public static DebuggerLaunchResultDto OpenCrash(Guid crashId, string kind = DebuggerTools.KindAuto)
    {
        var detail = CrashCatalog.GetDetail(crashId);
        if (detail is null)
            return Fail(kind, $"Crash not found: {crashId}");

        var dump = detail.Summary.MiniDumpPath ?? detail.Analysis?.DumpPath;
        if (string.IsNullOrWhiteSpace(dump) || !File.Exists(dump))
            return Fail(kind, "No minidump for this crash — replay/fuzz with dump capture first.");

        return OpenDump(dump, kind);
    }

    public static DebuggerLaunchResultDto Attach(int pid, string kind = DebuggerTools.KindAuto, bool go = true)
    {
        try
        {
            using var target = Process.GetProcessById(pid);
            if (target.HasExited)
                return Fail(kind, $"Process {pid} has already exited.");
        }
        catch (ArgumentException)
        {
            return Fail(kind, $"No process with PID {pid}.");
        }

        var resolvedKind = DebuggerTools.ResolveGuiKind(kind);
        var exe = DebuggerTools.ResolveGuiPath(resolvedKind);
        if (exe is null)
            return Fail(resolvedKind, "No debugger found to attach.");

        // -c "g" resumes so fuzzing can continue until the next break/crash.
        var cmd = go ? "-c \"g\"" : "";
        var args = $"-p {pid} {cmd}".Trim();
        try
        {
            var gui = resolvedKind is not DebuggerTools.KindCdb;
            var proc = Process.Start(DebuggerTools.BuildStartInfo(exe, args, gui));
            return new DebuggerLaunchResultDto(
                true, resolvedKind, exe, pid, null,
                $"Attached {resolvedKind} to PID {pid}" + (go ? " (g)" : " (broken in)"));
        }
        catch (Exception ex)
        {
            return Fail(resolvedKind, ex.Message, exe, pid: pid);
        }
    }

    public static DebuggerLaunchResultDto AttachProject(string projectName, string kind = DebuggerTools.KindAuto, bool go = true)
    {
        var pid = FindProjectPid(projectName);
        if (pid is null)
            return Fail(kind, $"No running process found for project '{projectName}'.");
        return Attach(pid.Value, kind, go);
    }

    public static int? FindProjectPid(string projectName)
    {
        var target = CrashCatalog.ListTargets()
            .FirstOrDefault(t => t.Name.Equals(projectName, StringComparison.OrdinalIgnoreCase));
        if (target is null || !File.Exists(target.ConfigPath))
            return null;

        var project = ProjectLoader.Load(target.ConfigPath);
        if (string.IsNullOrWhiteSpace(project.Target.Executable))
            return null;

        var exePath = ProjectLoader.ResolvePath(target.ConfigPath, project.Target.Executable);
        var name = Path.GetFileNameWithoutExtension(exePath);
        try
        {
            foreach (var p in Process.GetProcessesByName(name))
            {
                try
                {
                    if (!p.HasExited)
                        return p.Id;
                }
                catch
                {
                    /* ignore */
                }
            }
        }
        catch
        {
            /* ignore */
        }

        return null;
    }

    /// <summary>
    /// Start a headless watcher that writes a full dump on the next second-chance exception.
    /// Default: first-party <see cref="ScreamWatcher"/>. Optional fallbacks: procdump, cdb.
    /// </summary>
    public static DebuggerWaitHandle? StartWaitWatcher(int pid, string dumpsDir, string? preferred = null)
    {
        Directory.CreateDirectory(dumpsDir);
        preferred = (preferred ?? "scream").Trim().ToLowerInvariant();

        if (preferred is "scream" or "auto" or "")
            return DebuggerWaitHandle.FromScream(ScreamWatcher.Start(pid, dumpsDir));

        var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmssfff");
        var dumpPath = Path.Combine(dumpsDir, $"wait_{pid}_{stamp}.dmp");
        var procdump = DebuggerTools.FindProcDump();
        var cdb = DebuggerTools.FindCdb();

        if (preferred is "procdump" && procdump is not null)
            return StartProcDumpWait(procdump, pid, dumpPath);
        if (preferred is "cdb" && cdb is not null)
            return StartCdbWait(cdb, pid, dumpPath);

        // Unknown preference → scream
        return DebuggerWaitHandle.FromScream(ScreamWatcher.Start(pid, dumpsDir));
    }

    private static DebuggerWaitHandle StartProcDumpWait(string procdump, int pid, string dumpPath)
    {
        // -e: write on unhandled exception; -ma full dump; exit after one capture
        var args = $"-accepteula -ma -e -p {pid} -n 1 \"{dumpPath}\"";
        var psi = new ProcessStartInfo
        {
            FileName = procdump,
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        var proc = Process.Start(psi)
                   ?? throw new InvalidOperationException("Failed to start ProcDump");
        return new DebuggerWaitHandle(proc, dumpPath, "procdump");
    }

    private static DebuggerWaitHandle StartCdbWait(string cdb, int pid, string dumpPath)
    {
        // Attach, go; on next break write dump and quit/detach.
        var scriptPath = Path.Combine(Path.GetTempPath(), $"randfuzz_cdb_{pid}_{Guid.NewGuid():N}.txt");
        File.WriteAllText(scriptPath, $"""
            g
            .dump /ma "{dumpPath}"
            qd
            """);
        var args = $"-p {pid} -cf \"{scriptPath}\"";
        var psi = new ProcessStartInfo
        {
            FileName = cdb,
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        var proc = Process.Start(psi)
                   ?? throw new InvalidOperationException("Failed to start cdb");
        return new DebuggerWaitHandle(proc, dumpPath, "cdb", scriptPath);
    }

    public static async Task<string?> WaitForDumpAsync(
        DebuggerWaitHandle handle,
        int timeoutMs,
        CancellationToken cancellationToken = default)
    {
        if (handle.Completion is not null)
        {
            var completed = await Task.WhenAny(handle.Completion, Task.Delay(timeoutMs, cancellationToken));
            if (completed == handle.Completion)
                return await handle.Completion;
            return handle.TryExistingDump();
        }

        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var existing = handle.TryExistingDump();
            if (existing is not null)
                return existing;

            if (handle.Process is { HasExited: true })
                return handle.TryExistingDump();

            await Task.Delay(200, cancellationToken);
        }

        return handle.TryExistingDump();
    }

    private static DebuggerLaunchResultDto Fail(
        string kind,
        string message,
        string? path = null,
        string? dumpPath = null,
        int? pid = null) =>
        new(false, kind, path, pid, dumpPath, message);
}

/// <summary>Headless wait handle — Scream watcher, ProcDump, or cdb.</summary>
public sealed class DebuggerWaitHandle : IDisposable
{
    private readonly string? _scriptPath;
    private readonly ScreamWatcher? _scream;

    private DebuggerWaitHandle(
        Process? process,
        ScreamWatcher? scream,
        string dumpPath,
        string backend,
        string? scriptPath,
        Task<string?>? completion)
    {
        Process = process;
        _scream = scream;
        DumpPath = dumpPath;
        Backend = backend;
        _scriptPath = scriptPath;
        Completion = completion;
    }

    public static DebuggerWaitHandle FromScream(ScreamWatcher scream) =>
        new(null, scream, scream.DumpPath, "scream", null, scream.Completion);

    public DebuggerWaitHandle(Process process, string dumpPath, string backend, string? scriptPath = null)
        : this(process, null, dumpPath, backend, scriptPath, null)
    {
    }

    public Process? Process { get; }
    public ScreamWatcher? Scream => _scream;
    public string DumpPath { get; }
    public string Backend { get; }
    public Task<string?>? Completion { get; }

    public string? TryExistingDump()
    {
        if (File.Exists(DumpPath) && new FileInfo(DumpPath).Length > 0)
            return DumpPath;

        var dir = Path.GetDirectoryName(DumpPath);
        if (dir is null || !Directory.Exists(dir))
            return null;

        var prefix = Path.GetFileNameWithoutExtension(DumpPath);
        foreach (var candidate in Directory.EnumerateFiles(dir, prefix + "*.dmp"))
        {
            if (new FileInfo(candidate).Length > 0)
                return candidate;
        }

        return null;
    }

    public void Dispose()
    {
        _scream?.Dispose();
        if (Process is not null)
        {
            try
            {
                if (!Process.HasExited)
                    Process.Kill(entireProcessTree: true);
            }
            catch
            {
                /* ignore */
            }

            Process.Dispose();
        }

        if (_scriptPath is not null)
        {
            try { File.Delete(_scriptPath); } catch { /* ignore */ }
        }
    }
}
