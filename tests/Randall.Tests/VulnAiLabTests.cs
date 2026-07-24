using System.Diagnostics;
using System.Net.Sockets;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class VulnAiLabTests
{
    [Fact]
    public void InferBoom_ExitsWithScreamStatus()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var exe = Path.Combine(root, "targets", "vulnai", "randall-vulnai");
        if (!File.Exists(exe))
            exe = Path.Combine(root, "targets", "vulnai", "randall-vulnai.exe");
        if (!File.Exists(exe))
            return; // not built in this environment

        var boom = File.ReadAllBytes(Path.Combine(root, "projects", "seeds", "vulnai_infer_boom.bin"));
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = exe,
            Arguments = "-p 18775 --host 127.0.0.1",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });
        Assert.NotNull(proc);
        try
        {
            WaitTcp(18775, TimeSpan.FromSeconds(3));
            using var client = new TcpClient();
            client.Connect("127.0.0.1", 18775);
            using var stream = client.GetStream();
            var banner = new byte[64];
            _ = stream.Read(banner, 0, banner.Length);
            stream.Write(boom);
            stream.Flush();
            Assert.True(proc.WaitForExit(5000), "VulnAi should exit on INFER boom");
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
}
