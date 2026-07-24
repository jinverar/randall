using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class DefenseLabTests
{
    [Fact]
    public void TurretHelloBoom_ExitsWithScreamStatus()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var exe = Path.Combine(root, "targets", "vulnturret", "randall-vulnturret");
        if (!File.Exists(exe))
            exe = Path.Combine(root, "targets", "vulnturret", "randall-vulnturret.exe");
        if (!File.Exists(exe))
            return;

        var boom = File.ReadAllBytes(Path.Combine(root, "projects", "seeds", "vulnturret_hello_boom.bin"));
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = exe,
            Arguments = "-p 15670 --host 127.0.0.1 --mode tcp",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });
        Assert.NotNull(proc);
        try
        {
            WaitTcp(15670, TimeSpan.FromSeconds(3));
            using var client = new TcpClient();
            client.Connect("127.0.0.1", 15670);
            using var stream = client.GetStream();
            var banner = new byte[64];
            _ = stream.Read(banner, 0, banner.Length);
            stream.Write(boom);
            stream.Flush();
            Assert.True(proc.WaitForExit(5000), "VulnTurret should exit on HELLO boom");
            Assert.Equal(139, proc.ExitCode);
        }
        finally
        {
            TryKill(proc);
        }
    }

    [Fact]
    public void UasHelloBoom_ExitsWithScreamStatus()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var exe = Path.Combine(root, "targets", "vulnuas", "randall-vulnuas");
        if (!File.Exists(exe))
            exe = Path.Combine(root, "targets", "vulnuas", "randall-vulnuas.exe");
        if (!File.Exists(exe))
            return;

        var boom = File.ReadAllBytes(Path.Combine(root, "projects", "seeds", "vulnuas_hello_boom.bin"));
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = exe,
            Arguments = "-p 15671 --host 127.0.0.1 --mode tcp",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });
        Assert.NotNull(proc);
        try
        {
            WaitTcp(15671, TimeSpan.FromSeconds(3));
            using var client = new TcpClient();
            client.Connect("127.0.0.1", 15671);
            using var stream = client.GetStream();
            var banner = new byte[64];
            _ = stream.Read(banner, 0, banner.Length);
            stream.Write(boom);
            stream.Flush();
            Assert.True(proc.WaitForExit(5000), "VulnUas should exit on HELLO boom");
            Assert.Equal(139, proc.ExitCode);
        }
        finally
        {
            TryKill(proc);
        }
    }

    [Fact]
    public void TurretUdpPoseBoom_ExitsWithScreamStatus()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var exe = Path.Combine(root, "targets", "vulnturret", "randall-vulnturret");
        if (!File.Exists(exe))
            exe = Path.Combine(root, "targets", "vulnturret", "randall-vulnturret.exe");
        if (!File.Exists(exe))
            return;

        var boom = File.ReadAllBytes(Path.Combine(root, "projects", "seeds", "vulnturret_udp_pose_boom.bin"));
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = exe,
            Arguments = "-p 15672 --host 127.0.0.1 --mode udp",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });
        Assert.NotNull(proc);
        try
        {
            Thread.Sleep(200);
            using var udp = new UdpClient();
            udp.Send(boom, boom.Length, new IPEndPoint(IPAddress.Loopback, 15672));
            Assert.True(proc.WaitForExit(5000), "VulnTurret UDP should exit on pose boom");
            Assert.Equal(139, proc.ExitCode);
        }
        finally
        {
            TryKill(proc);
        }
    }

    private static void WaitTcp(int port, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                using var c = new TcpClient();
                c.Connect("127.0.0.1", port);
                return;
            }
            catch
            {
                Thread.Sleep(50);
            }
        }

        throw new TimeoutException($"port {port} not accepting");
    }

    private static void TryKill(Process proc)
    {
        try
        {
            if (!proc.HasExited)
                proc.Kill(entireProcessTree: true);
        }
        catch { /* ignore */ }
    }
}
