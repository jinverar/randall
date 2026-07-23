using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Start/stop/status for Randall lab vuln servers (randall-vuln*).
/// Catalog metadata lives in <see cref="LabCatalog"/>; defaults to loopback bind.
/// </summary>
public static class LabServerManager
{
    private static readonly ConcurrentDictionary<string, int> PidsWeStarted = new(StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyList<LabServerInfoDto> List(string? repoRoot = null, string? category = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        IEnumerable<LabCatalog.Def> q = LabCatalog.All;
        if (!string.IsNullOrWhiteSpace(category) && !category.Equals("all", StringComparison.OrdinalIgnoreCase))
            q = q.Where(d => d.Category.Equals(category, StringComparison.OrdinalIgnoreCase));
        return q.Select(d => Describe(d, repoRoot)).ToList();
    }

    public static LabLibraryListDto Library(string? repoRoot = null, string? category = null)
    {
        var labs = List(repoRoot, category);
        return new LabLibraryListDto(
            labs,
            LabCatalog.Categories(),
            labs.Count(l => l.Running),
            labs.Count(l => l.ExeExists));
    }

    public static LabServerActionResultDto Start(string id, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var def = LabCatalog.Find(id);
        if (def is null)
            return new LabServerActionResultDto(false, $"Unknown lab: {id}", id);
        if (!def.Startable)
            return new LabServerActionResultDto(false, $"{def.Name} is a profile-only entry (not startable).", id);

        var existing = FindRunning(def);
        if (existing is not null)
        {
            PidsWeStarted[def.Id] = existing.Id;
            return new LabServerActionResultDto(true,
                $"{def.Name} already running (PID {existing.Id}) on :{def.Port}", def.Id, existing.Id);
        }

        var exeDeclared = Path.GetFullPath(Path.Combine(repoRoot, def.ExeRelativePath.Replace('/', Path.DirectorySeparatorChar)));
        var exe = ExecutableResolver.FindExisting(exeDeclared);
        if (exe is null)
        {
            var hint = def.BuildHint ?? $"scripts/build-{def.Id}.ps1 (or build-all-lab-targets.ps1 / build-lab-targets.sh)";
            return new LabServerActionResultDto(false,
                $"Executable missing: {def.ExeRelativePath}. Build with: {hint}",
                def.Id);
        }

        var args = new List<string> { "-p", def.Port.ToString(), "--host", "127.0.0.1" };
        if (def.ExtraArgs is { Length: > 0 })
            args.AddRange(def.ExtraArgs);

        var st = TargetRuntimeService.Start(new TargetRuntimeStartRequest(
            Id: def.Id,
            Executable: exe,
            Args: args.ToArray(),
            WorkingDirectory: Path.GetDirectoryName(exe),
            WaitPort: def.Port,
            WaitHost: "127.0.0.1",
            WaitProtocol: def.Protocol,
            ProjectYaml: def.ProjectYaml));

        if (st.Pid is int pid)
            PidsWeStarted[def.Id] = pid;
        else if (!st.Ok)
            PidsWeStarted.TryRemove(def.Id, out _);

        return new LabServerActionResultDto(st.Ok, st.Message, def.Id, st.Pid);
    }

    public static LabServerActionResultDto Stop(string id)
    {
        var def = LabCatalog.Find(id);
        if (def is null)
            return new LabServerActionResultDto(false, $"Unknown lab: {id}", id);

        if (TargetRuntimeService.IsManagedRunning(def.Id) || TargetRuntimeService.Status(def.Id).Executable is not null)
        {
            var st = TargetRuntimeService.Stop(def.Id);
            ProcessTreeKill.TryKillPortListeners(def.Port, def.Protocol, out _);
            foreach (var p in FindStopTargets(def))
            {
                try
                {
                    if (!p.HasExited)
                    {
                        ProcessTreeKill.TryKillTree(p.Id, out _);
                        p.WaitForExit(3000);
                    }
                }
                catch { /* ignore */ }
                finally { p.Dispose(); }
            }

            PidsWeStarted.TryRemove(def.Id, out _);
            return new LabServerActionResultDto(st.Ok, st.Message, def.Id, st.Pid);
        }

        var portListeners = ProcessTreeKill.TryKillPortListeners(def.Port, def.Protocol, out _);
        var procs = FindStopTargets(def);
        if (procs.Count == 0 && portListeners.Count == 0)
        {
            // Shared binary may still be the only signal — if port is down, we are done.
            if (ProcessNameIsShared(def) && !IsReachable(def))
            {
                PidsWeStarted.TryRemove(def.Id, out _);
                return new LabServerActionResultDto(true, $"{def.Name} is not running", def.Id);
            }

            if (!ProcessNameIsShared(def))
            {
                PidsWeStarted.TryRemove(def.Id, out _);
                return new LabServerActionResultDto(true, $"{def.Name} is not running", def.Id);
            }
        }

        var killed = portListeners.Count;
        foreach (var p in procs)
        {
            try
            {
                if (!p.HasExited)
                {
                    ProcessTreeKill.TryKillTree(p.Id, out _);
                    p.WaitForExit(3000);
                    killed++;
                }
            }
            catch (Exception ex)
            {
                return new LabServerActionResultDto(false,
                    $"Stop failed for PID {p.Id}: {ex.Message}", def.Id, p.Id);
            }
            finally
            {
                p.Dispose();
            }
        }

        PidsWeStarted.TryRemove(def.Id, out _);
        return new LabServerActionResultDto(true,
            killed > 0 ? $"Stopped {def.Name} ({killed} process(es))" : $"{def.Name} stopped",
            def.Id);
    }

    public static LabServerActionResultDto StopAll()
    {
        var notes = new List<string>();
        var ok = true;
        foreach (var def in LabCatalog.Startable())
        {
            var r = Stop(def.Id);
            notes.Add(r.Message);
            if (!r.Ok) ok = false;
        }

        return new LabServerActionResultDto(ok, string.Join("; ", notes), "all");
    }

    private static LabServerInfoDto Describe(LabCatalog.Def def, string repoRoot)
    {
        var exeDeclared = Path.GetFullPath(Path.Combine(repoRoot, def.ExeRelativePath.Replace('/', Path.DirectorySeparatorChar)));
        var exe = ExecutableResolver.FindExisting(exeDeclared);
        var exeExists = exe is not null;
        var proc = FindRunning(def);
        var running = proc is not null;
        var pid = proc?.Id;
        if (running && pid is int p)
            PidsWeStarted[def.Id] = p;

        var reachable = running && IsReachable(def);
        string? note = null;
        if (!exeExists)
            note = "Build: " + (def.BuildHint ?? ("scripts/build-" + def.Id + ".ps1"));
        else if (!def.Startable)
            note = "Profile-only — fuzz with: randall fuzz -c " + def.ProjectYaml.Replace('\\', '/');
        else if (running && !reachable)
            note = "Process up but port not accepting yet";
        else if (running)
            note = "Listening on 127.0.0.1";

        var bindHint = def.Startable ? "127.0.0.1" : "profile";

        return new LabServerInfoDto(
            def.Id,
            def.Name,
            def.Description,
            def.Port,
            def.Protocol,
            def.ProcessName,
            def.ExeRelativePath.Replace('\\', '/'),
            def.ProjectYaml.Replace('\\', '/'),
            exeExists,
            running,
            pid,
            reachable,
            bindHint,
            note,
            def.Category,
            def.Difficulty,
            def.Tags,
            def.DocsPath,
            def.BuildHint,
            def.Startable);
    }

    private static bool ProcessNameIsShared(LabCatalog.Def def) =>
        LabCatalog.All.Count(d => d.ProcessName.Equals(def.ProcessName, StringComparison.OrdinalIgnoreCase)) > 1;

    private static Process? FindRunning(LabCatalog.Def def)
    {
        // Profile-only / file labs have no long-lived listener.
        if (!def.Startable || string.IsNullOrWhiteSpace(def.ProcessName) || def.Port <= 0)
            return null;

        // Prefer the PID we started for this catalog id (shared binaries like vulndrone udp/tcp).
        if (PidsWeStarted.TryGetValue(def.Id, out var knownPid))
        {
            try
            {
                var known = Process.GetProcessById(knownPid);
                if (!known.HasExited)
                    return known;
                known.Dispose();
            }
            catch
            {
                /* gone */
            }

            PidsWeStarted.TryRemove(def.Id, out _);
        }

        var candidates = FindAllRunning(def);
        if (candidates.Count == 0)
            return null;

        // Shared ProcessName: only treat as this lab when its port is accepting.
        if (ProcessNameIsShared(def))
        {
            if (IsReachable(def))
                return candidates[0];
            foreach (var p in candidates)
                p.Dispose();
            return null;
        }

        foreach (var extra in candidates.Skip(1))
            extra.Dispose();
        return candidates[0];
    }

    private static List<Process> FindAllRunning(LabCatalog.Def def)
    {
        var list = new List<Process>();
        try
        {
            foreach (var p in Process.GetProcessesByName(def.ProcessName))
            {
                try
                {
                    if (!p.HasExited)
                        list.Add(p);
                    else
                        p.Dispose();
                }
                catch
                {
                    p.Dispose();
                }
            }
        }
        catch
        {
            /* ignore enumeration failures */
        }

        return list;
    }

    /// <summary>Processes to stop for this lab — never kill sibling labs that share a binary.</summary>
    private static List<Process> FindStopTargets(LabCatalog.Def def)
    {
        if (PidsWeStarted.TryGetValue(def.Id, out var knownPid))
        {
            try
            {
                var known = Process.GetProcessById(knownPid);
                if (!known.HasExited)
                    return [known];
                known.Dispose();
            }
            catch
            {
                /* gone */
            }
        }

        if (ProcessNameIsShared(def))
            return []; // port kill below handles listeners; avoid stopping sibling modes

        return FindAllRunning(def);
    }

    private static bool IsReachable(LabCatalog.Def def)
    {
        if (!def.Startable || def.Port <= 0 ||
            def.Protocol.Equals("file", StringComparison.OrdinalIgnoreCase))
            return false;

        try
        {
            if (def.Protocol.Equals("udp", StringComparison.OrdinalIgnoreCase))
            {
                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = 400;
                udp.Connect(IPAddress.Loopback, def.Port);
                udp.Send([0x00, 0x01], 2);
                return true;
            }

            using var tcp = new TcpClient();
            var task = tcp.ConnectAsync(IPAddress.Loopback, def.Port);
            return task.Wait(800) && tcp.Connected;
        }
        catch
        {
            return false;
        }
    }
}
