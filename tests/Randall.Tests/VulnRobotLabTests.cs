using System.Diagnostics;
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
            Arguments = "-p 15570 --host 127.0.0.1",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });
        Assert.NotNull(proc);
        try
        {
            WaitPort(15570, TimeSpan.FromSeconds(3));
            using var client = new TcpClient();
            client.Connect("127.0.0.1", 15570);
            using var stream = client.GetStream();
            // consume banner
            var banner = new byte[64];
            _ = stream.Read(banner, 0, banner.Length);
            stream.Write(boom);
            stream.Flush();
            Assert.True(proc.WaitForExit(5000), "VulnRobot should exit on HELLO boom");
            Assert.Equal(139, proc.ExitCode);
        }
        finally
        {
            try
            {
                if (!proc.HasExited)
                    proc.Kill(entireProcessTree: true);
            }
            catch { /* ignore */ }
        }
    }

    private static void WaitPort(int port, TimeSpan timeout)
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
}
