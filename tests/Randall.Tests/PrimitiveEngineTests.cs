using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class PrimitiveEngineTests
{
    [Fact]
    public void Build_ascii_write_yields_write_candidate_and_maturity()
    {
        var id = Guid.NewGuid();
        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Attempt to write to address 41414141\nParameter[1]: 41414141\n",
            regs: "rax=0000000041414141\nrip=00000000401020\n",
            stack: "00000000`0012ff00 00000000`00401000 lab!Parse+0x10",
            disasm: "00401020  mov dword ptr [rax], ecx");

        var root = RootCauseEngine.Build(id, "lab", null, null, obs, null, null);
        var influence = InfluenceEngine.Build(id, "lab", null, null, obs, null, null, null, null, null);
        var report = PrimitiveEngine.Build(id, "lab", influence, root, obs);

        Assert.True(report.Ok);
        Assert.True(report.Maturity >= ResearchMaturity.R1);
        Assert.Contains(report.Primitives, p =>
            p.Kind is PrimitiveKind.InputInfluencedWrite or PrimitiveKind.PointerControl
                or PrimitiveKind.RegisterControl);
        Assert.False(string.IsNullOrWhiteSpace(report.Summary));
        Assert.Contains("R", report.Maturity.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Maturity_chip_and_teaching_labels_cover_R0_through_R7()
    {
        Assert.Equal("Crash", PrimitiveEngine.MaturityChipLabel(ResearchMaturity.R0));
        Assert.Equal("Triaged", PrimitiveEngine.MaturityChipLabel(ResearchMaturity.R1));
        Assert.Equal("Root cause", PrimitiveEngine.MaturityChipLabel(ResearchMaturity.R2));
        Assert.Equal("Attributed", PrimitiveEngine.MaturityChipLabel(ResearchMaturity.R3));
        Assert.Equal("Primitive", PrimitiveEngine.MaturityChipLabel(ResearchMaturity.R4));
        Assert.Equal("Observed", PrimitiveEngine.MaturityChipLabel(ResearchMaturity.R5));
        Assert.Equal("Confirmed", PrimitiveEngine.MaturityChipLabel(ResearchMaturity.R6));
        Assert.Equal("Research package", PrimitiveEngine.MaturityChipLabel(ResearchMaturity.R7));

        foreach (ResearchMaturity level in Enum.GetValues<ResearchMaturity>())
        {
            Assert.False(string.IsNullOrWhiteSpace(PrimitiveEngine.MaturityLabel(level)));
            Assert.False(string.IsNullOrWhiteSpace(PrimitiveEngine.MaturityTeachingBlurb(level)));
            Assert.Contains("R", level.ToString(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public void PersistForCrash_round_trips_json()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randfuzz-prim-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            var obs = ScreamInvestigator.ParseBlocks(
                "EXCEPTION_CODE: (c0000005)\n",
                exr: "Attempt to write to address 41414141\n",
                regs: "rip=0000000041414141\n");
            var report = PrimitiveEngine.PersistForCrash(dir, id, "lab", null, null, obs);
            var loaded = PrimitiveEngine.TryReadForCrash(dir, id);
            Assert.NotNull(loaded);
            Assert.Equal(report.Maturity, loaded!.Maturity);
            Assert.Equal(report.Summary, loaded.Summary);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }
}
