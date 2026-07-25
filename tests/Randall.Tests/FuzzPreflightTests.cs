using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public sealed class FuzzPreflightTests
{
    [Fact]
    public void ValidateTargetExecutable_fails_before_recorders_for_missing_longLived_lab()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-preflight-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var yaml = Path.Combine(dir, "vulnftp.yaml");
        File.WriteAllText(yaml,
            """
            name: vulnftp
            kind: tcp
            target:
              executable: ../targets/vulnftp/randall-vulnftp.exe
              longLived: true
            transport:
              type: tcp
              host: 127.0.0.1
              port: 2121
            """);

        try
        {
            var project = ProjectLoader.Load(yaml);
            var error = FuzzPreflight.ValidateTargetExecutable(project, yaml, dryRun: false);

            Assert.NotNull(error);
            Assert.Contains("not found", error, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("build-vulnftp", error, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void ValidateTargetExecutable_skips_dry_run_and_in_process()
    {
        var project = new ProjectConfig
        {
            Name = "vulnftp",
            Kind = "tcp",
            Target = new TargetConfig
            {
                Executable = "../targets/vulnftp/randall-vulnftp.exe",
                LongLived = true,
            },
        };

        Assert.Null(FuzzPreflight.ValidateTargetExecutable(project, "projects/x.yaml", dryRun: true));

        var harness = new ProjectConfig
        {
            Name = "harness-demo",
            Kind = "harness",
            Target = new TargetConfig { Executable = "../missing/app.exe" },
        };
        Assert.Null(FuzzPreflight.ValidateTargetExecutable(harness, "projects/x.yaml", dryRun: false));
    }
}
