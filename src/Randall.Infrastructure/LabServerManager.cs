using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Start/stop/status for Randall lab vuln servers (randall-vuln*).
/// Defaults to loopback bind for public-WiFi safety.
/// </summary>
public static class LabServerManager
{
    private static readonly ConcurrentDictionary<string, int> PidsWeStarted = new(StringComparer.OrdinalIgnoreCase);

    private sealed record LabDef(
        string Id,
        string Name,
        string Description,
        int Port,
        string Protocol,
        string ProcessName,
        string ExeRelativePath,
        string ProjectYaml);

    private static readonly LabDef[] Catalog =
    [
        new("vulnserver", "Vulnserver", "TCP command lab (TRUN/GMON/…)", 9999, "tcp",
            "randall-vulnserver", "targets/vulnserver/randall-vulnserver.exe", "projects/vulnserver.yaml"),
        new("vulnhttp", "VulnHttp", "HTTP/1.1 parser lab", 8080, "tcp",
            "randall-vulnhttp", "targets/vulnhttp/randall-vulnhttp.exe", "projects/vulnhttp.yaml"),
        new("vulnftp", "VulnFtp", "FTP session lab", 2121, "tcp",
            "randall-vulnftp", "targets/vulnftp/randall-vulnftp.exe", "projects/vulnftp.yaml"),
        new("vulnssh", "VulnSsh", "SSH-shaped stub lab", 2222, "tcp",
            "randall-vulnssh", "targets/vulnssh/randall-vulnssh.exe", "projects/vulnssh.yaml"),
        new("vulntftp", "VulnTftp", "UDP TFTP RRQ/WRQ lab", 6969, "udp",
            "randall-vulntftp", "targets/vulntftp/randall-vulntftp.exe", "projects/vulntftp.yaml"),
        new("vulnrpc", "VulnRpc", "DCE-shaped RPC lab", 1355, "tcp",
            "randall-vulnrpc", "targets/vulnrpc/randall-vulnrpc.exe", "projects/vulnrpc.yaml"),
        new("vulnsmb", "VulnSmb", "NBSS+SMB2 + pipe→DCE lab", 4455, "tcp",
            "randall-vulnsmb", "targets/vulnsmb/randall-vulnsmb.exe", "projects/vulnsmb.yaml"),
    ];

    public static IReadOnlyList<LabServerInfoDto> List(string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        return Catalog.Select(d => Describe(d, repoRoot)).ToList();
    }

    public static LabServerActionResultDto Start(string id, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var def = Find(id);
        if (def is null)
            return new LabServerActionResultDto(false, $"Unknown lab: {id}", id);

        var existing = FindRunning(def);
        if (existing is not null)
        {
            PidsWeStarted[def.Id] = existing.Id;
            return new LabServerActionResultDto(true,
                $"{def.Name} already running (PID {existing.Id}) on :{def.Port}", def.Id, existing.Id);
        }

        var exe = Path.GetFullPath(Path.Combine(repoRoot, def.ExeRelativePath.Replace('/', Path.DirectorySeparatorChar)));
        if (!File.Exists(exe))
        {
            return new LabServerActionResultDto(false,
                $"Executable missing: {def.ExeRelativePath}. Run scripts/build-{def.Id}.ps1 (or build-all-lab-targets.ps1).",
                def.Id);
        }

        // Labs are presets on Target Runtime (loopback bind for public-WiFi safety)
        var st = TargetRuntimeService.Start(new TargetRuntimeStartRequest(
            Id: def.Id,
            Executable: exe,
            Args: ["-p", def.Port.ToString(), "--host", "127.0.0.1"],
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
        var def = Find(id);
        if (def is null)
            return new LabServerActionResultDto(false, $"Unknown lab: {id}", id);

        // Prefer Target Runtime slot (clean ownership), then fall back to process-name kill
        if (TargetRuntimeService.IsManagedRunning(def.Id) || TargetRuntimeService.Status(def.Id).Executable is not null)
        {
            var st = TargetRuntimeService.Stop(def.Id);
            ProcessTreeKill.TryKillPortListeners(def.Port, def.Protocol, out _);
            // Also clear orphans with the same image name
            foreach (var p in FindAllRunning(def))
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

        var procs = FindAllRunning(def);
        if (procs.Count == 0)
        {
            PidsWeStarted.TryRemove(def.Id, out _);
            return new LabServerActionResultDto(true, $"{def.Name} is not running", def.Id);
        }

        var killed = 0;
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
            $"Stopped {def.Name} ({killed} process(es))", def.Id);
    }

    public static LabServerActionResultDto StopAll()
    {
        var notes = new List<string>();
        var ok = true;
        foreach (var def in Catalog)
        {
            var r = Stop(def.Id);
            notes.Add(r.Message);
            if (!r.Ok) ok = false;
        }

        return new LabServerActionResultDto(ok, string.Join("; ", notes), "all");
    }

    private static LabServerInfoDto Describe(LabDef def, string repoRoot)
    {
        var exe = Path.GetFullPath(Path.Combine(repoRoot, def.ExeRelativePath.Replace('/', Path.DirectorySeparatorChar)));
        var exeExists = File.Exists(exe);
        var proc = FindRunning(def);
        var running = proc is not null;
        var pid = proc?.Id;
        if (running && pid is int p)
            PidsWeStarted[def.Id] = p;

        var reachable = running && IsReachable(def);
        string? note = null;
        if (!exeExists)
            note = "Build with scripts/build-" + def.Id + ".ps1";
        else if (running && !reachable)
            note = "Process up but port not accepting yet";
        else if (running)
            note = "Listening (prefer 127.0.0.1 — stop if you started an older all-interfaces build)";

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
            "127.0.0.1",
            note);
    }

    private static LabDef? Find(string id) =>
        Catalog.FirstOrDefault(d => d.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    private static Process? FindRunning(LabDef def) =>
        FindAllRunning(def).FirstOrDefault();

    private static List<Process> FindAllRunning(LabDef def)
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

    private static bool IsReachable(LabDef def)
    {
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
