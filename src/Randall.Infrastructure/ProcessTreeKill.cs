using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace Randall.Infrastructure;

/// <summary>
/// Best-effort process-tree termination with fallbacks when <see cref="Process.Kill(bool)"/>
/// hits "Access is denied" on some children (common with debuggers / recorders attached).
/// Also finds and kills TCP/UDP listeners holding a lab port.
/// </summary>
internal static class ProcessTreeKill
{
    private static readonly Regex TcpListenLine = new(
        @"^\s*TCP\s+\S+:(?<port>\d+)\s+\S+\s+LISTENING\s+(?<pid>\d+)\s*$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Regex UdpBindLine = new(
        @"^\s*UDP\s+\S+:(?<port>\d+)\s+\S+\s+(?<pid>\d+)\s*$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static bool IsAlive(int pid)
    {
        if (pid <= 0)
            return false;
        try
        {
            using var p = Process.GetProcessById(pid);
            return !p.HasExited;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Kill pid and descendants; returns true when the root pid is no longer alive.</summary>
    public static bool TryKillTree(int pid, out string? error)
    {
        error = null;
        if (pid <= 0 || !IsAlive(pid))
            return true;

        if (TryKillViaProcessApi(pid, out error))
            return true;

        if (OperatingSystem.IsWindows())
        {
            if (TryTaskKill(pid, out error))
                return true;
            if (TryTerminateProcess(pid, out error))
                return true;
        }

        if (!IsAlive(pid))
        {
            error = null;
            return true;
        }

        error ??= "process still alive after kill attempts";
        return false;
    }

    public static IReadOnlyList<int> FindListeningPids(int port, string protocol)
    {
        if (!OperatingSystem.IsWindows() || port <= 0)
            return [];

        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "netstat.exe",
                Arguments = "-ano",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            if (proc is null)
                return [];

            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(8000);

            var pids = new HashSet<int>();
            var portText = port.ToString();
            var isUdp = protocol.Equals("udp", StringComparison.OrdinalIgnoreCase);
            foreach (var raw in output.Split('\n'))
            {
                var line = raw.TrimEnd('\r');
                var m = isUdp ? UdpBindLine.Match(line) : TcpListenLine.Match(line);
                if (!m.Success || m.Groups["port"].Value != portText)
                    continue;
                if (int.TryParse(m.Groups["pid"].Value, out var pid) && pid > 0)
                    pids.Add(pid);
            }

            return pids.ToList();
        }
        catch
        {
            return [];
        }
    }

    /// <summary>Kill any process listening on port (Windows netstat). Returns killed root pids.</summary>
    public static IReadOnlyList<int> TryKillPortListeners(int port, string protocol, out string? error)
    {
        error = null;
        var killed = new List<int>();
        foreach (var pid in FindListeningPids(port, protocol))
        {
            if (TryKillTree(pid, out var killErr))
                killed.Add(pid);
            else if (!string.IsNullOrWhiteSpace(killErr))
                error = killErr;
        }

        return killed;
    }

    /// <summary>Wait until host:port is not accepting; optionally kill listeners first.</summary>
    public static bool WaitUntilPortFree(
        string host,
        int port,
        string protocol,
        TimeSpan timeout,
        bool killListeners = false)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (!ProbePort(host, port, protocol))
                return true;

            if (killListeners)
                TryKillPortListeners(port, protocol, out _);

            Thread.Sleep(100);
        }

        if (killListeners)
            TryKillPortListeners(port, protocol, out _);

        return !ProbePort(host, port, protocol);
    }

    private static bool TryKillViaProcessApi(int pid, out string? error)
    {
        error = null;
        try
        {
            using var p = Process.GetProcessById(pid);
            if (p.HasExited)
                return true;
            p.Kill(entireProcessTree: true);
            p.WaitForExit(5000);
            return !IsAlive(pid);
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return !IsAlive(pid);
        }
    }

    private static bool TryTaskKill(int pid, out string? error)
    {
        error = null;
        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "taskkill.exe",
                Arguments = $"/PID {pid} /T /F",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            if (proc is null)
            {
                error = "taskkill failed to start";
                return !IsAlive(pid);
            }

            var stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit(8000);
            if (!IsAlive(pid))
                return true;

            if (!string.IsNullOrWhiteSpace(stderr))
                error = stderr.Trim();
            return false;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return !IsAlive(pid);
        }
    }

    private static bool TryTerminateProcess(int pid, out string? error)
    {
        error = null;
        var h = OpenProcess(Native.ProcessTerminate, false, pid);
        if (h == IntPtr.Zero)
        {
            error = $"OpenProcess failed (pid {pid})";
            return !IsAlive(pid);
        }

        try
        {
            if (!TerminateProcess(h, 1))
            {
                error = $"TerminateProcess failed (pid {pid})";
                return !IsAlive(pid);
            }

            for (var i = 0; i < 30 && IsAlive(pid); i++)
                Thread.Sleep(100);
            return !IsAlive(pid);
        }
        finally
        {
            CloseHandle(h);
        }
    }

    private static bool ProbePort(string host, int port, string protocol)
    {
        try
        {
            if (protocol.Equals("udp", StringComparison.OrdinalIgnoreCase))
            {
                using var udp = new System.Net.Sockets.UdpClient();
                udp.Client.ReceiveTimeout = 400;
                udp.Connect(host, port);
                udp.Send([0x00, 0x01], 2);
                return true;
            }

            using var tcp = new System.Net.Sockets.TcpClient();
            var task = tcp.ConnectAsync(host, port);
            return task.Wait(800) && tcp.Connected;
        }
        catch
        {
            return false;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private static class Native
    {
        public const uint ProcessTerminate = 0x0001;
    }
}
