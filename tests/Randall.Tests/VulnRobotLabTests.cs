using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class VulnRobotLabTests
{
    [Fact]
    public void HelloBoom_ExitsWithScreamStatus()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var exe = Path.Combine(root, "targets", "vulnrobot", "randall-vulnrobot");
        if (!File.Exists(exe))
            exe = Path.Combine(root, "targets", "vulnrobot", "randall-vulnrobot.exe");
        if (!File.Exists(exe))
            return; // not built in this environment

        var boom = File.ReadAllBytes(Path.Combine(root, "projects", "seeds", "vulnrobot_hello_boom.bin"));
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = exe,
            Arguments = "-p 15570 --host 127.0.0.1 --mode tcp",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });
        Assert.NotNull(proc);
        try
        {
            WaitTcp(15570, TimeSpan.FromSeconds(3));
            using var client = new TcpClient();
            client.Connect("127.0.0.1", 15570);
            using var stream = client.GetStream();
            var banner = new byte[64];
            _ = stream.Read(banner, 0, banner.Length);
            stream.Write(boom);
            stream.Flush();
            Assert.True(proc.WaitForExit(5000), "VulnRobot should exit on HELLO boom");
            Assert.Equal(139, proc.ExitCode);
        }
        finally
        {
            TryKill(proc);
        }
    }

    [Fact]
    public void UdpPoseBoom_ExitsWithScreamStatus()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var exe = Path.Combine(root, "targets", "vulnrobot", "randall-vulnrobot");
        if (!File.Exists(exe))
            exe = Path.Combine(root, "targets", "vulnrobot", "randall-vulnrobot.exe");
        if (!File.Exists(exe))
            return;

        var boom = File.ReadAllBytes(Path.Combine(root, "projects", "seeds", "vulnrobot_udp_pose_boom.bin"));
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = exe,
            Arguments = "-p 15571 --host 127.0.0.1 --mode udp",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });
        Assert.NotNull(proc);
        try
        {
            Thread.Sleep(200);
            using var udp = new UdpClient();
            udp.Send(boom, boom.Length, new IPEndPoint(IPAddress.Loopback, 15571));
            Assert.True(proc.WaitForExit(5000), "VulnRobot UDP should exit on pose boom");
            Assert.Equal(139, proc.ExitCode);
        }
        finally
        {
            TryKill(proc);
        }
    }

    [Fact]
    public void RosBusTopicBoom_ExitsWithScreamStatus()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var exe = Path.Combine(root, "targets", "vulnrosbus", "randall-vulnrosbus");
        if (!File.Exists(exe))
            exe = Path.Combine(root, "targets", "vulnrosbus", "randall-vulnrosbus.exe");
        if (!File.Exists(exe))
            return;

        var boom = File.ReadAllBytes(Path.Combine(root, "projects", "seeds", "vulnrosbus_topic_boom.bin"));
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = exe,
            Arguments = "-p 15572 --host 127.0.0.1",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });
        Assert.NotNull(proc);
        try
        {
            WaitTcp(15572, TimeSpan.FromSeconds(3));
            using var client = new TcpClient();
            client.Connect("127.0.0.1", 15572);
            using var stream = client.GetStream();
            stream.Write(boom);
            stream.Flush();
            Assert.True(proc.WaitForExit(5000), "VulnRosBus should exit on topic boom");
            Assert.Equal(139, proc.ExitCode);
        }
        finally
        {
            TryKill(proc);
        }
    }

    [Fact]
    public void RobotIoReadBoom_ExitsWithScreamStatus()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var exe = Path.Combine(root, "targets", "vulnrobotio", "randall-vulnrobotio");
        if (!File.Exists(exe))
            exe = Path.Combine(root, "targets", "vulnrobotio", "randall-vulnrobotio.exe");
        if (!File.Exists(exe))
            return;

        var boom = File.ReadAllBytes(Path.Combine(root, "projects", "seeds", "vulnrobotio_read_boom.bin"));
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = exe,
            Arguments = "-p 15573 --host 127.0.0.1",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });
        Assert.NotNull(proc);
        try
        {
            WaitTcp(15573, TimeSpan.FromSeconds(3));
            using var client = new TcpClient();
            client.Connect("127.0.0.1", 15573);
            using var stream = client.GetStream();
            stream.Write(boom);
            stream.Flush();
            Assert.True(proc.WaitForExit(5000), "VulnRobotIo should exit on READ boom");
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
