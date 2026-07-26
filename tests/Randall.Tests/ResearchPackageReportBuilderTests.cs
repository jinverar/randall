using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class ResearchPackageReportBuilderTests
{
    [Fact]
    public void BuildForCrash_includes_advisor_packages_and_ethics_note()
    {
        var id = Guid.NewGuid();
        var advisor = new ExploitabilityAdvisorDto(
            true,
            id,
            "lab",
            ExploitabilityAdvisorLabel.Study,
            "MEDIUM",
            [TeachingPackages.BoundsStudy, TeachingPackages.NoWeaponization],
            ["ascii write suggests bounds study"],
            ["debugger:write"],
            DateTimeOffset.UtcNow,
            "Study bounds");

        var report = ResearchPackageReportBuilder.BuildForCrash(id, "lab", advisor);

        Assert.True(report.Ok);
        Assert.Contains(report.Packages, p => p.Title.Contains("bounds", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(report.Packages, p => p.Id == "pkg-ethics");
        Assert.DoesNotContain("shellcode", report.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.All(report.Packages, p =>
        {
            // Ethics package mentions forbidden words as a teaching reminder — skip it.
            if (p.Id == "pkg-ethics") return;
            Assert.DoesNotContain("ROP", p.Description, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("shellcode", p.Description, StringComparison.OrdinalIgnoreCase);
        });
    }

    [Fact]
    public void PersistForCrash_round_trips()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randfuzz-rpkg-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            var written = ResearchPackageReportBuilder.PersistForCrash(dir, id, "lab");
            var loaded = ResearchPackageReportBuilder.TryRead(
                ResearchPackageReportBuilder.PathForCrash(dir, id));
            Assert.NotNull(loaded);
            Assert.Equal(written.Summary, loaded!.Summary);
            Assert.Equal(written.Packages.Count, loaded.Packages.Count);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }
}
