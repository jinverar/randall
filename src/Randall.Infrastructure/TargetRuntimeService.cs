using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Target Runtime — own start / stop / restart / status for arbitrary executables.
/// Slots persist under <c>data/runtime-slots.json</c> so CLI / serve / agent on the
/// same machine share ownership across process boundaries.
/// </summary>
public static class TargetRuntimeService
{
    private static readonly ConcurrentDictionary<string, Slot> Slots = new(StringComparer.OrdinalIgnoreCase);
    private static readonly object Gate = new();
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };
    private static bool _loaded;

    private sealed class Slot
    {
        public required string Id { get; init; }
        public required string Executable { get; set; }
        public required List<string> Args { get; set; }
        public string? WorkingDirectory { get; set; }
        public int? WaitPort { get; set; }
        public string WaitHost { get; set; } = "127.0.0.1";
        public string WaitProtocol { get; set; } = "tcp";
        public bool PageHeap { get; set; }
        public string? ProjectYaml { get; set; }
        public List<PostStartActionConfig> PostStart { get; set; } = [];
        public string? CasePath { get; set; }
        public string? PageHeapNote { get; set; }
        public Process? Process { get; set; }
        public int? LastKnownPid { get; set; }
        public DateTimeOffset? StartedAtUtc { get; set; }
        public DateTimeOffset? StoppedAtUtc { get; set; }
        public int? LastExitCode { get; set; }
        public string? LastMessage { get; set; }
    }

    private sealed record PersistedSlot(
        string Id,
        string Executable,
        List<string> Args,
        string? WorkingDirectory,
        int? WaitPort,
        string? WaitHost,
        string? WaitProtocol,
        bool PageHeap,
        string? ProjectYaml,
        int? Pid,
        DateTimeOffset? StartedAtUtc,
        DateTimeOffset? StoppedAtUtc,
        int? LastExitCode,
        string? LastMessage,
        List<PostStartActionConfig>? PostStart = null,
        string? CasePath = null,
        string? PageHeapNote = null);

    private sealed record PersistedFile(List<PersistedSlot> Slots);

    public static TargetRuntimeListDto List()
    {
        EnsureLoaded();
        RefreshExited();
        var slots = Slots.Values
            .OrderBy(s => s.Id, StringComparer.OrdinalIgnoreCase)
            .Select(Describe)
            .ToList();
        return new TargetRuntimeListDto(Environment.MachineName, slots);
    }

    public static TargetRuntimeStatusDto Status(string id)
    {
        EnsureLoaded();
        RefreshExited();
        if (!Slots.TryGetValue(id, out var slot))
        {
            return new TargetRuntimeStatusDto(
                id, true, "No runtime slot with this id", false, null, null, null, null,
                null, null, null, false, null, null, null, null, Environment.MachineName);
        }

        return Describe(slot);
    }

    public static TargetRuntimeStatusDto Start(TargetRuntimeStartRequest request, string? repoRoot = null)
    {
        EnsureLoaded(repoRoot);
        if (string.IsNullOrWhiteSpace(request.Id))
            return Fail(request.Id ?? "", "Id is required");
        if (string.IsNullOrWhiteSpace(request.Executable))
            return Fail(request.Id, "Executable is required");

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var exe = ResolveExecutable(request.Executable, repoRoot);
        if (!File.Exists(exe))
            return Fail(request.Id, $"Executable not found: {exe}");

        RefreshExited();
        if (Slots.TryGetValue(request.Id, out var existing) && IsAlive(existing.Process))
        {
            existing.LastMessage = $"Already running (PID {existing.Process!.Id})";
            Persist();
            return Describe(existing);
        }

        if (Slots.TryGetValue(request.Id, out var dead) && dead.Process is not null)
        {
            try { dead.Process.Dispose(); } catch { /* ignore */ }
            dead.Process = null;
        }

        var args = request.Args?.ToList() ?? [];
        var workDir = string.IsNullOrWhiteSpace(request.WorkingDirectory)
            ? Path.GetDirectoryName(exe)!
            : ResolvePath(request.WorkingDirectory!, repoRoot);

        string? pageHeapNote = null;
        if (request.PageHeap)
        {
            var ph = PageHeapEnabler.TryEnableForExecutable(exe);
            pageHeapNote = ph.Message;
            if (!ph.Ok && !ph.Applied)
                return Fail(request.Id, ph.Message);
        }

        try
        {
            // UseShellExecute so the target is not killed when the parent CLI/job exits.
            // (dotnet run often places children in a kill-on-close job object.)
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = string.Join(' ', args.Select(EscapeArg)),
                WorkingDirectory = workDir,
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };

            var proc = Process.Start(psi);
            if (proc is null)
                return Fail(request.Id, "Process.Start returned null");

            var slot = new Slot
            {
                Id = request.Id.Trim(),
                Executable = exe,
                Args = args,
                WorkingDirectory = workDir,
                WaitPort = request.WaitPort,
                WaitHost = string.IsNullOrWhiteSpace(request.WaitHost) ? "127.0.0.1" : request.WaitHost!,
                WaitProtocol = string.IsNullOrWhiteSpace(request.WaitProtocol) ? "tcp" : request.WaitProtocol!,
                PageHeap = request.PageHeap,
                PageHeapNote = pageHeapNote,
                ProjectYaml = request.ProjectYaml,
                PostStart = request.PostStart?.ToList() ?? [],
                CasePath = request.CasePath,
                Process = proc,
                LastKnownPid = proc.Id,
                StartedAtUtc = DateTimeOffset.UtcNow,
                LastMessage = "Started",
            };

            // UseShellExecute can delay the real entrypoint; give bind a moment before HasExited.
            Thread.Sleep(400);
            if (proc.HasExited)
            {
                slot.LastExitCode = proc.ExitCode;
                slot.StoppedAtUtc = DateTimeOffset.UtcNow;
                slot.LastKnownPid = proc.Id;
                slot.Process = null;
                slot.LastMessage = $"Exited immediately (code {proc.ExitCode})";
                Slots[slot.Id] = slot;
                try { proc.Dispose(); } catch { /* ignore */ }
                Persist();
                return Describe(slot) with { Ok = false };
            }

            if (slot.WaitPort is int port)
            {
                var reachable = WaitForPort(slot.WaitHost, port, slot.WaitProtocol, TimeSpan.FromSeconds(3));
                // ProbePort sees *any* listener — re-check our process so a stale orphan is not "success".
                if (proc.HasExited)
                {
                    slot.LastExitCode = proc.ExitCode;
                    slot.StoppedAtUtc = DateTimeOffset.UtcNow;
                    slot.LastKnownPid = proc.Id;
                    slot.Process = null;
                    slot.LastMessage = reachable
                        ? $"Exited during bind (code {proc.ExitCode}); {slot.WaitHost}:{port} still has another listener"
                        : $"Exited during bind (code {proc.ExitCode})";
                    Slots[slot.Id] = slot;
                    try { proc.Dispose(); } catch { /* ignore */ }
                    Persist();
                    return Describe(slot) with { Ok = false };
                }

                slot.LastMessage = reachable
                    ? $"Started PID {proc.Id}; {slot.WaitHost}:{port} accepting"
                    : $"Started PID {proc.Id}; waiting for {slot.WaitHost}:{port} (not accepting yet)";
            }
            else
            {
                slot.LastMessage = $"Started PID {proc.Id}";
            }

            if (!string.IsNullOrWhiteSpace(pageHeapNote))
                slot.LastMessage += " · " + pageHeapNote;

            if (slot.PostStart.Count > 0)
            {
                var ctx = new PostStartContext(
                    proc.Id, slot.Id, exe, slot.WaitHost, slot.WaitPort,
                    slot.CasePath, workDir, repoRoot);
                var steps = PostStartRunner.Run(slot.PostStart, ctx);
                var failed = steps.Where(s => !s.Ok).ToList();
                slot.LastMessage += failed.Count == 0
                    ? $" · postStart ok ({steps.Count})"
                    : $" · postStart issues: {string.Join("; ", failed.Select(f => f.Message))}";
            }

            Slots[slot.Id] = slot;
            Persist();
            return Describe(slot);
        }
        catch (Exception ex)
        {
            return Fail(request.Id, $"Start failed: {ex.Message}");
        }
    }

    public static TargetRuntimeStatusDto StartFromProject(string yamlPath, string? idOverride = null)
    {
        var repoRoot = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        if (!Path.IsPathRooted(yamlPath))
            yamlPath = Path.Combine(repoRoot, yamlPath.Replace('/', Path.DirectorySeparatorChar));
        yamlPath = Path.GetFullPath(yamlPath);
        if (!File.Exists(yamlPath))
            return Fail(idOverride ?? "", $"Project not found: {yamlPath}");

        ProjectConfig project;
        try
        {
            project = ProjectLoader.Load(yamlPath);
        }
        catch (Exception ex)
        {
            return Fail(idOverride ?? Path.GetFileNameWithoutExtension(yamlPath), $"YAML load failed: {ex.Message}");
        }

        var id = string.IsNullOrWhiteSpace(idOverride) ? project.Name : idOverride!;
        if (string.IsNullOrWhiteSpace(id))
            id = Path.GetFileNameWithoutExtension(yamlPath);

        if (string.IsNullOrWhiteSpace(project.Target.Executable))
            return Fail(id, "Project has empty target.executable — nothing to start");

        var exe = ProjectLoader.ResolvePath(yamlPath, project.Target.Executable);
        var workDir = string.IsNullOrWhiteSpace(project.Target.WorkingDirectory)
            ? Path.GetDirectoryName(exe)
            : ProjectLoader.ResolvePath(yamlPath, project.Target.WorkingDirectory);

        int? waitPort = project.Kind is "tcp" or "udp" ? project.Transport.Port : null;
        var waitHost = string.IsNullOrWhiteSpace(project.Transport.Host) ? "127.0.0.1" : project.Transport.Host;

        return Start(new TargetRuntimeStartRequest(
            Id: id,
            Executable: exe,
            Args: project.Target.Args,
            WorkingDirectory: workDir,
            WaitPort: waitPort,
            WaitHost: waitHost,
            PageHeap: project.Target.PageHeap,
            ProjectYaml: yamlPath.Replace('\\', '/'),
            WaitProtocol: project.Kind,
            PostStart: project.Target.PostStart));
    }

    public static TargetRuntimeStatusDto Stop(string id)
    {
        EnsureLoaded();
        RefreshExited();
        if (!Slots.TryGetValue(id, out var slot))
            return Fail(id, "No runtime slot with this id");

        if (!IsAlive(slot.Process))
        {
            // Try kill by last known pid if we lost the handle
            if (slot.LastKnownPid is int orphanPid)
                TryKillPid(orphanPid, slot.WaitPort, slot.WaitProtocol);

            slot.LastMessage = "Already stopped";
            slot.Process = null;
            Persist();
            return Describe(slot);
        }

        try
        {
            var pid = slot.Process!.Id;
            try { slot.LastExitCode = slot.Process.HasExited ? slot.Process.ExitCode : null; }
            catch { /* ignore */ }

            var killOk = ProcessTreeKill.TryKillTree(pid, out var killErr);
            if (!killOk && slot.WaitPort is int stopPort)
            {
                ProcessTreeKill.TryKillPortListeners(stopPort, slot.WaitProtocol, out _);
                killOk = !ProcessTreeKill.IsAlive(pid);
            }

            try { slot.Process.WaitForExit(3000); } catch { /* ignore */ }
            slot.Process.Dispose();
            slot.Process = null;
            slot.LastKnownPid = pid;
            slot.StoppedAtUtc = DateTimeOffset.UtcNow;
            slot.LastMessage = killOk
                ? $"Stopped (was PID {pid})"
                : $"Stopped PID {pid} with warnings: {killErr ?? "some tree processes may remain"}";
            Persist();
            return Describe(slot);
        }
        catch (Exception ex)
        {
            return Fail(id, $"Stop failed: {ex.Message}");
        }
    }

    public static TargetRuntimeStatusDto Restart(string id)
    {
        EnsureLoaded();
        RefreshExited();
        if (!Slots.TryGetValue(id, out var slot))
            return Fail(id, "No runtime slot with this id — start first");

        var req = new TargetRuntimeStartRequest(
            Id: slot.Id,
            Executable: slot.Executable,
            Args: slot.Args,
            WorkingDirectory: slot.WorkingDirectory,
            WaitPort: slot.WaitPort,
            WaitHost: slot.WaitHost,
            PageHeap: slot.PageHeap,
            ProjectYaml: slot.ProjectYaml,
            WaitProtocol: slot.WaitProtocol,
            PostStart: slot.PostStart,
            CasePath: slot.CasePath);

        if (IsAlive(slot.Process) || slot.LastKnownPid is not null)
            Stop(id);

        // Avoid WSAEADDRINUSE when the previous listener has not released the port yet.
        if (req.WaitPort is int waitPort)
        {
            var host = string.IsNullOrWhiteSpace(req.WaitHost) ? "127.0.0.1" : req.WaitHost!;
            var proto = string.IsNullOrWhiteSpace(req.WaitProtocol) ? "tcp" : req.WaitProtocol!;
            if (!WaitUntilPortFree(host, waitPort, proto, TimeSpan.FromSeconds(8), killListeners: true))
            {
                return Fail(id,
                    $"Restart blocked: {host}:{waitPort} still accepting (stop labs/orphan listeners on this port)");
            }
        }
        else
        {
            Thread.Sleep(300);
        }

        return Start(req);
    }

    public static TargetRuntimeStatusDto StopAll()
    {
        EnsureLoaded();
        RefreshExited();
        var notes = new List<string>();
        var ok = true;
        foreach (var id in Slots.Keys.ToList())
        {
            var r = Stop(id);
            notes.Add($"{id}: {r.Message}");
            if (!r.Ok) ok = false;
        }

        return new TargetRuntimeStatusDto(
            "all", ok, string.Join("; ", notes), false, null, null, null, null,
            null, null, null, false, null, null, null, null, Environment.MachineName);
    }

    public static Process? TryGetProcess(string id)
    {
        EnsureLoaded();
        RefreshExited();
        return Slots.TryGetValue(id, out var slot) && IsAlive(slot.Process) ? slot.Process : null;
    }

    public static bool IsManagedRunning(string id)
    {
        EnsureLoaded();
        RefreshExited();
        return Slots.TryGetValue(id, out var slot) && IsAlive(slot.Process);
    }

    private static TargetRuntimeStatusDto Describe(Slot slot)
    {
        var running = IsAlive(slot.Process);
        int? pid = running ? slot.Process!.Id : slot.LastKnownPid;
        if (running)
            pid = slot.Process!.Id;
        else if (!running)
            pid = null;

        bool? reachable = null;
        if (running && slot.WaitPort is int port)
            reachable = ProbePort(slot.WaitHost, port, slot.WaitProtocol);

        return new TargetRuntimeStatusDto(
            Id: slot.Id,
            Ok: true,
            Message: slot.LastMessage ?? (running ? "Running" : "Stopped"),
            Running: running,
            Pid: pid,
            Executable: slot.Executable,
            Args: slot.Args,
            WorkingDirectory: slot.WorkingDirectory,
            WaitPort: slot.WaitPort,
            WaitHost: slot.WaitHost,
            PortReachable: reachable,
            PageHeap: slot.PageHeap,
            ProjectYaml: slot.ProjectYaml,
            StartedAtUtc: slot.StartedAtUtc,
            LastExitCode: slot.LastExitCode,
            StoppedAtUtc: running ? null : slot.StoppedAtUtc,
            MachineName: Environment.MachineName);
    }

    private static TargetRuntimeStatusDto Fail(string id, string message) =>
        new(id, false, message, false, null, null, null, null,
            null, null, null, false, null, null, null, null, Environment.MachineName);

    private static void EnsureLoaded(string? repoRoot = null)
    {
        if (_loaded) return;
        lock (Gate)
        {
            if (_loaded) return;
            Load(repoRoot);
            _loaded = true;
        }
    }

    private static string StatePath(string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var dir = Path.Combine(repoRoot, "data");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, "runtime-slots.json");
    }

    private static void Load(string? repoRoot)
    {
        var path = StatePath(repoRoot);
        if (!File.Exists(path))
            return;

        try
        {
            var json = File.ReadAllText(path);
            var file = JsonSerializer.Deserialize<PersistedFile>(json, JsonOpts);
            if (file?.Slots is null) return;

            foreach (var p in file.Slots)
            {
                if (string.IsNullOrWhiteSpace(p.Id)) continue;
                var slot = new Slot
                {
                    Id = p.Id,
                    Executable = p.Executable,
                    Args = p.Args ?? [],
                    WorkingDirectory = p.WorkingDirectory,
                    WaitPort = p.WaitPort,
                    WaitHost = p.WaitHost ?? "127.0.0.1",
                    WaitProtocol = p.WaitProtocol ?? "tcp",
                    PageHeap = p.PageHeap,
                    PageHeapNote = p.PageHeapNote,
                    ProjectYaml = p.ProjectYaml,
                    PostStart = p.PostStart ?? [],
                    CasePath = p.CasePath,
                    LastKnownPid = p.Pid,
                    StartedAtUtc = p.StartedAtUtc,
                    StoppedAtUtc = p.StoppedAtUtc,
                    LastExitCode = p.LastExitCode,
                    LastMessage = p.LastMessage,
                };

                if (p.Pid is int pid)
                {
                    try
                    {
                        var proc = Process.GetProcessById(pid);
                        if (!proc.HasExited)
                        {
                            slot.Process = proc;
                            slot.LastMessage = p.LastMessage ?? $"Reattached PID {pid}";
                        }
                        else
                        {
                            proc.Dispose();
                            slot.StoppedAtUtc ??= DateTimeOffset.UtcNow;
                            slot.LastMessage = p.LastMessage ?? "Process exited";
                        }
                    }
                    catch
                    {
                        slot.StoppedAtUtc ??= DateTimeOffset.UtcNow;
                        slot.LastMessage = p.LastMessage ?? "Process no longer present";
                    }
                }

                Slots[slot.Id] = slot;
            }
        }
        catch
        {
            /* corrupt state — start fresh */
        }
    }

    private static void Persist()
    {
        lock (Gate)
        {
            try
            {
                var list = Slots.Values.Select(s => new PersistedSlot(
                    s.Id,
                    s.Executable,
                    s.Args,
                    s.WorkingDirectory,
                    s.WaitPort,
                    s.WaitHost,
                    s.WaitProtocol,
                    s.PageHeap,
                    s.ProjectYaml,
                    IsAlive(s.Process) ? s.Process!.Id : s.LastKnownPid,
                    s.StartedAtUtc,
                    s.StoppedAtUtc,
                    s.LastExitCode,
                    s.LastMessage,
                    s.PostStart,
                    s.CasePath,
                    s.PageHeapNote)).ToList();

                var path = StatePath();
                var tmp = path + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(new PersistedFile(list), JsonOpts));
                File.Move(tmp, path, overwrite: true);
            }
            catch
            {
                /* best-effort */
            }
        }
    }

    private static void RefreshExited()
    {
        var dirty = false;
        foreach (var slot in Slots.Values)
        {
            if (slot.Process is null)
            {
                // Re-try attach from LastKnownPid (another process may have started it)
                if (slot.LastKnownPid is int pid)
                {
                    try
                    {
                        var proc = Process.GetProcessById(pid);
                        if (!proc.HasExited)
                        {
                            slot.Process = proc;
                            dirty = true;
                        }
                        else
                            proc.Dispose();
                    }
                    catch { /* gone */ }
                }

                continue;
            }

            try
            {
                if (slot.Process.HasExited)
                {
                    try { slot.LastExitCode = slot.Process.ExitCode; } catch { /* ignore */ }
                    slot.LastKnownPid = slot.Process.Id;
                    slot.StoppedAtUtc = DateTimeOffset.UtcNow;
                    slot.LastMessage ??= $"Exited (code {slot.LastExitCode})";
                    try { slot.Process.Dispose(); } catch { /* ignore */ }
                    slot.Process = null;
                    dirty = true;
                }
            }
            catch
            {
                slot.Process = null;
                dirty = true;
            }
        }

        if (dirty)
            Persist();
    }

    private static bool IsAlive(Process? p)
    {
        if (p is null) return false;
        try { return !p.HasExited; }
        catch { return false; }
    }

    private static void TryKillPid(int pid, int? waitPort = null, string? waitProtocol = null)
    {
        ProcessTreeKill.TryKillTree(pid, out _);
        if (waitPort is int port)
            ProcessTreeKill.TryKillPortListeners(port, waitProtocol ?? "tcp", out _);
    }

    private static string ResolveExecutable(string path, string repoRoot)
    {
        path = path.Trim().Trim('"');
        if (Path.IsPathRooted(path))
            return Path.GetFullPath(path);
        return Path.GetFullPath(Path.Combine(repoRoot, path.Replace('/', Path.DirectorySeparatorChar)));
    }

    private static string ResolvePath(string path, string repoRoot)
    {
        path = path.Trim().Trim('"');
        if (Path.IsPathRooted(path))
            return Path.GetFullPath(path);
        return Path.GetFullPath(Path.Combine(repoRoot, path.Replace('/', Path.DirectorySeparatorChar)));
    }

    private static string EscapeArg(string a) =>
        a.Contains(' ') || a.Contains('"') ? $"\"{a.Replace("\"", "\\\"")}\"" : a;

    private static bool WaitForPort(string host, int port, string protocol, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (ProbePort(host, port, protocol))
                return true;
            Thread.Sleep(150);
        }

        return false;
    }

    /// <summary>True when nothing accepts on host:port (safe to bind a new listener).</summary>
    private static bool WaitUntilPortFree(
        string host,
        int port,
        string protocol,
        TimeSpan timeout,
        bool killListeners = false) =>
        ProcessTreeKill.WaitUntilPortFree(host, port, protocol, timeout, killListeners);

    private static bool ProbePort(string host, int port, string protocol)
    {
        try
        {
            if (protocol.Equals("udp", StringComparison.OrdinalIgnoreCase))
            {
                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = 400;
                udp.Connect(host, port);
                udp.Send([0x00, 0x01], 2);
                return true;
            }

            using var tcp = new TcpClient();
            var task = tcp.ConnectAsync(host, port);
            return task.Wait(800) && tcp.Connected;
        }
        catch
        {
            return false;
        }
    }
}
