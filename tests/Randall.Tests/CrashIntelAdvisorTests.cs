using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class CrashIntelAdvisorTests
{
    [Fact]
    public void Build_IncludesGdbAndExploitTestSections()
    {
        var project = new ProjectConfig
        {
            Name = "vulnturret",
            Kind = "tcp",
            Target = new TargetConfig { Executable = "../targets/vulnturret/randall-vulnturret" },
            Transport = new TransportConfig { Host = "127.0.0.1", Port = 15660 },
        };
        var result = new TargetRunResult(true, 139, null, "server exited (SIGSEGV / 139)");
        var payload = new byte[75];
        Array.Fill(payload, (byte)'A');

        var intel = CrashIntelAdvisor.Build(
            project,
            "projects/vulnturret.yaml",
            "HELLO",
            "boundary",
            payload,
            result,
            exePath: "targets/vulnturret/randall-vulnturret",
            crashId: Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));

        Assert.Contains("boundary", intel.Hypothesis, StringComparison.OrdinalIgnoreCase);
        Assert.NotEmpty(intel.Findings);
        Assert.Contains(intel.ExploitTestRecommendations, r => r.Contains("cyclic", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(intel.GdbCommands, g => g.Contains("bt full", StringComparison.Ordinal));
        Assert.Contains(intel.GdbCommands, g => g.Contains("info registers", StringComparison.Ordinal));
        Assert.Contains(intel.NextCliCommands, c => c.Contains("scream walk", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(intel.NextCliCommands, c => c.Contains("checksec", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(intel.ExploitTestRecommendations, r =>
            r.Contains("shellcode", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("Triage", intel.Disclaimer, StringComparison.OrdinalIgnoreCase);

        var text = CrashIntelAdvisor.FormatConsole(intel);
        Assert.Contains("EXPLOIT-TEST RECOMMENDATIONS", text);
        Assert.Contains("GDB COMMANDS", text);
        Assert.Contains("NEXT CLI", text);
    }

    [Fact]
    public void WriteIntelFiles_CreatesTxtBesideCrashes()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-intel-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var intel = new CrashIntelDto(
                "test headline",
                "test hyp",
                ["finding"],
                ["probe"],
                ["gdb -q"],
                ["randall checksec --exe x"]);
            var id = Guid.NewGuid();
            var path = CrashIntelAdvisor.WriteIntelFiles(dir, id, "demo", 1, "DEADBEEF", intel);
            Assert.True(File.Exists(path));
            Assert.True(File.Exists(Path.Combine(dir, $"{id:N}_intel.txt")));
            Assert.Contains("GDB COMMANDS", File.ReadAllText(path));
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }
}
