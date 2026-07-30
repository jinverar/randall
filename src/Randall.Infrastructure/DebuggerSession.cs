using System.Collections.Concurrent;
using System.Diagnostics;
using Randall.Contracts;
using Randall.Infrastructure.Rop;

namespace Randall.Infrastructure;

/// <summary>
/// Launch WinDbg / WinDbg Preview / cdb / ProcDump for attach, wait-for-crash, and dump open.
/// Research triage only — no exploit automation.
/// </summary>
public static class DebuggerSession
{
    private static readonly ConcurrentDictionary<string, int> OpenDumpProcesses = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// GUI dump open follows <paramref name="openOnCrash"/> / fuzz.debuggerOpenOnCrash only.
    /// <c>debuggerMode: both</c> enables Scream wait like <c>wait</c>; it does not imply GUI open.
    /// </summary>
    public static bool ShouldOpenDumpOnCrash(bool openOnCrash) => openOnCrash;

    /// <summary>Cap auto-open storms during high crash rates (fuzz loop still saves dumps + headless cdb).</summary>
    public const int MaxConcurrentAutoOpenDumps = 2;

    public static DebuggerLaunchResultDto OpenDump(string dumpPath, string kind = DebuggerTools.KindAuto, Guid? crashId = null)
    {
        var usable = CrashDumpPaths.Sanitize(dumpPath);
        if (usable is null)
        {
            var expected = string.IsNullOrWhiteSpace(dumpPath)
                ? "(no path)"
                : Path.GetFullPath(dumpPath);
            return Fail(kind,
                $"No usable dump at: {expected}. " +
                "Capture one with Debugger Mode Wait/Both (Scream), then retry " +
                "`randall debug open -d <file.dmp>` or Crashes → WinDbg Preview.");
        }

        dumpPath = Path.GetFullPath(usable);

        if (TryReuseOpenDump(dumpPath, out var existing))
            return existing!;

        if (OpenDumpProcesses.Count >= MaxConcurrentAutoOpenDumps)
        {
            return Fail(kind,
                $"{OpenDumpProcesses.Count} debugger windows already open (max {MaxConcurrentAutoOpenDumps}) — " +
                "close one or open dumps manually from the Crashes tab");
        }

        var resolvedKind = DebuggerTools.ResolveGuiKind(kind);
        var exe = DebuggerTools.ResolveGuiPath(resolvedKind);
        if (exe is null)
            return Fail(resolvedKind, "No WinDbg / WinDbg Preview / cdb found. Install Debugging Tools for Windows or WinDbg Preview.");

        var openScript = crashId is { } id
            ? RandfuzzDbgWalk.TryWriteOpenScript(id)
            : null;

        var symArgs = OperatingSystem.IsWindows() ? DebuggerTools.FormatSymbolCommandLineArgs() : "";
        var args = BuildOpenArgs(symArgs, dumpPath, openScript, resolvedKind);
        try
        {
            // Fire-and-forget: never block the fuzz loop waiting on a debugger console/GUI.
            var proc = Process.Start(DebuggerTools.BuildDetachedStartInfo(exe, args));
            if (proc?.Id is { } pid)
                OpenDumpProcesses[dumpPath] = pid;
            var msg = openScript is not null
                ? $"Opened dump in {resolvedKind} with Randfuzz metadata script: {dumpPath}"
                : $"Opened dump in {resolvedKind}: {dumpPath}";
            return new DebuggerLaunchResultDto(
                true, resolvedKind, exe, proc?.Id, dumpPath,
                msg);
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

        var dump = ResolveCrashDumpPath(detail, crashId);
        if (dump is null)
        {
            var expected = detail.Summary.MiniDumpPath
                           ?? detail.Analysis?.DumpPath
                           ?? detail.Sidecar?.MiniDumpPath
                           ?? ExpectedDumpHint(detail);
            return Fail(kind,
                $"No usable minidump for crash {crashId:N}. Expected: {expected}. " +
                "Re-fuzz with Debugger Mode Wait or Both (Scream) so a .dmp is written under data/crashes/<project>/dumps/.");
        }

        return OpenDump(dump, kind, crashId);
    }

    /// <summary>
    /// Prefer CrashArtifactIdentity dump path when present, then catalog summary/analysis/sidecar.
    /// </summary>
    internal static string? ResolveCrashDumpPath(CrashDetailDto detail, Guid crashId)
    {
        var crashesDir = Path.GetDirectoryName(detail.Summary.InputPath);
        if (crashesDir is not null)
        {
            var identity = CrashArtifactIdentityService.TryReadIdentity(crashesDir, crashId);
            var fromIdentity = CrashDumpPaths.Sanitize(identity?.DumpPath);
            if (fromIdentity is not null)
                return Path.GetFullPath(fromIdentity);
        }

        var fromCatalog = CrashCatalog.ResolveDumpPath(detail);
        return fromCatalog is null ? null : Path.GetFullPath(fromCatalog);
    }

    private static string ExpectedDumpHint(CrashDetailDto detail)
    {
        var dir = Path.GetDirectoryName(detail.Summary.InputPath);
        if (string.IsNullOrWhiteSpace(dir))
            return $"data/crashes/{detail.Summary.Project}/dumps/*.dmp";
        return Path.Combine(dir, "dumps", "*.dmp");
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
        var symArgs = OperatingSystem.IsWindows() ? DebuggerTools.FormatSymbolCommandLineArgs() : "";
        var args = string.IsNullOrEmpty(symArgs)
            ? $"-p {pid} {cmd}".Trim()
            : $"{symArgs} -p {pid} {cmd}".Trim();
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
        var scriptPath = CdbScriptBuilder.WriteTempScript(
            CdbProbePlan.WaitAttach,
            new CdbScriptOptions { DumpPath = dumpPath },
            prefix: $"randfuzz_cdb_{pid}");
        var args = $"-p {pid} -cf \"{scriptPath}\"";
        if (OperatingSystem.IsWindows())
            args = $"{DebuggerTools.FormatSymbolCommandLineArgs()} {args}";
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

    private static bool TryReuseOpenDump(string dumpPath, out DebuggerLaunchResultDto? result)
    {
        result = null;
        if (!OpenDumpProcesses.TryGetValue(dumpPath, out var pid))
            return false;

        try
        {
            using var proc = Process.GetProcessById(pid);
            if (proc.HasExited)
            {
                OpenDumpProcesses.TryRemove(dumpPath, out _);
                return false;
            }

            var name = proc.ProcessName;
            if (!IsDebuggerProcessName(name))
            {
                OpenDumpProcesses.TryRemove(dumpPath, out _);
                return false;
            }

            string? exePath = null;
            try { exePath = proc.MainModule?.FileName; } catch { /* elevated / UWP */ }

            result = new DebuggerLaunchResultDto(
                true, "reuse", exePath, pid, dumpPath,
                $"Dump already open in {name} (PID {pid}) — close it or End task to reopen");
            return true;
        }
        catch
        {
            OpenDumpProcesses.TryRemove(dumpPath, out _);
            return false;
        }
    }

    private static bool IsDebuggerProcessName(string name) =>
        name.Equals("windbg", StringComparison.OrdinalIgnoreCase)
        || name.Equals("cdb", StringComparison.OrdinalIgnoreCase)
        || name.Equals("WinDbgX", StringComparison.OrdinalIgnoreCase)
        || name.Equals("DbgX.Shell", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Build WinDbg/cdb dump-open arguments. <c>-z</c> is always first.
    /// GUI tools must not use cdb's <c>-cf</c> — WinDbg Preview treats it as unknown and
    /// opens an empty "Debuggee not connected" window instead of loading the dump.
    /// Use <c>-c "$$&gt;&lt;script"</c> for WinDbg / Preview; keep <c>-cf</c> for cdb only.
    /// </summary>
    internal static string BuildOpenArgs(
        string symArgs,
        string dumpPath,
        string? scriptPath,
        string resolvedKind = DebuggerTools.KindWinDbgPreview)
    {
        var parts = new List<string> { $"-z \"{dumpPath}\"" };
        if (!string.IsNullOrEmpty(symArgs))
            parts.Add(symArgs);
        if (!string.IsNullOrWhiteSpace(scriptPath))
        {
            if (string.Equals(resolvedKind, DebuggerTools.KindCdb, StringComparison.OrdinalIgnoreCase))
                parts.Add($"-cf \"{scriptPath}\"");
            else
            {
                var fwd = scriptPath.Replace('\\', '/');
                parts.Add($"-c \"$$><{fwd}\"");
            }
        }

        return string.Join(' ', parts);
    }
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
