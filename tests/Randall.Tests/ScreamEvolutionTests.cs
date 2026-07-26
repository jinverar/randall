using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class ScreamEvolutionTests
{
    [Fact]
    public void ClassifyProgression_ReadWriteControlled_Ladder()
    {
        var readDbg = MakeDebugger("fn", DebuggerAccessKind.Read, "stack-1", DebuggerAddressClass.NullPage);
        var writeDbg = readDbg with { Access = DebuggerAccessKind.Write };
        var controlledDbg = writeDbg with
        {
            FaultAddressClass = DebuggerAddressClass.AsciiPattern,
            SuspectedInputInfluence = "HIGH",
        };

        Assert.Equal(ScreamProgressionStep.ReadViolation,
            ScreamEvolutionBuilder.ClassifyProgression(null, readDbg, null));
        Assert.Equal(ScreamProgressionStep.WriteViolation,
            ScreamEvolutionBuilder.ClassifyProgression(null, writeDbg, null));
        Assert.Equal(ScreamProgressionStep.ControlledAddress,
            ScreamEvolutionBuilder.ClassifyProgression(null, controlledDbg, null));
        Assert.Equal(ScreamProgressionStep.PatternDepth,
            ScreamEvolutionBuilder.ClassifyProgression(null, controlledDbg,
                new CrashCorruptionChainDto(true, Guid.NewGuid(), "p", "HIGH", "x", null, null, 128, null, [], [], null, null, DateTimeOffset.UtcNow)));
    }

    [Fact]
    public void ComputeMomentum_ImprovingProgression_ScoresHigher()
    {
        var warming = ScreamEvolutionBuilder.ComputeMomentum(
            ScreamProgressionStep.WriteViolation,
            ScreamProgressionStep.ReadViolation,
            ScreamProgressionStep.ReadViolation,
            progressionDelta: 1,
            screamScore: 55,
            ancestorScreamScore: 40,
            debugger: null,
            triage: null);

        var stable = ScreamEvolutionBuilder.ComputeMomentum(
            ScreamProgressionStep.ReadViolation,
            ScreamProgressionStep.ReadViolation,
            ScreamProgressionStep.ReadViolation,
            progressionDelta: 0,
            screamScore: 40,
            ancestorScreamScore: 40,
            debugger: null,
            triage: null);

        Assert.True(warming > stable);
        Assert.True(warming >= 25);
        Assert.Equal("warming", ScreamEvolutionBuilder.LabelMomentum(45, 1));
    }

    [Fact]
    public void Build_FamilyMembership_GroupsByPhenotypeNotIpCluster()
    {
        var idA = Guid.NewGuid();
        var idB = Guid.NewGuid();
        var fn = "vuln!copy_buffer";

        var sidecarA = MakeSidecar(idA, "hash-a", "parent-root", ["havoc", "expand"]);
        var sidecarB = MakeSidecar(idB, "hash-b", "hash-a", ["havoc", "expand", "bitflip"]);

        var dbgA = MakeDebugger(fn, DebuggerAccessKind.Read, "stack-abc", DebuggerAddressClass.NullPage);
        var dbgB = MakeDebugger(fn, DebuggerAccessKind.Write, "stack-abc", DebuggerAddressClass.NullPage);

        var ctxA = new ScreamEvolutionBuilder.CrashContext(
            idA, "demo", sidecarA, null, dbgA, null, "hash-a", 0, DateTimeOffset.UtcNow.AddHours(-1));
        var ctxB = new ScreamEvolutionBuilder.CrashContext(
            idB, "demo", sidecarB, null, dbgB, null, "hash-b", 0, DateTimeOffset.UtcNow);

        var keyA = ScreamEvolutionBuilder.ComputeFamilyKey(ctxA);
        var keyB = ScreamEvolutionBuilder.ComputeFamilyKey(ctxB);
        Assert.Equal(keyA, keyB);

        var evoB = ScreamEvolutionBuilder.Build(
            idB, "demo", sidecarB, null, dbgB, null, [ctxA, ctxB]);

        Assert.True(evoB.Ok);
        Assert.Equal(2, evoB.FamilySize);
        Assert.Contains(idA, evoB.FamilyMemberIds);
        Assert.Contains(idB, evoB.FamilyMemberIds);
        Assert.Equal(2, evoB.Generation);
        Assert.Equal(idA, evoB.AncestorCrashId);
        Assert.True(evoB.ProgressionDelta > 0);
        Assert.True(evoB.MomentumScore >= 25);
        Assert.Contains(evoB.MomentumLabel, new[] { "warming", "hot", "stable" });
    }

    [Fact]
    public void Build_DifferentFunction_SeparateFamilies()
    {
        var idA = Guid.NewGuid();
        var idB = Guid.NewGuid();

        var dbgA = MakeDebugger("mod!fn_a", DebuggerAccessKind.Read, "stack-1");
        var dbgB = MakeDebugger("mod!fn_b", DebuggerAccessKind.Read, "stack-1");

        var ctxA = new ScreamEvolutionBuilder.CrashContext(
            idA, "demo", MakeSidecar(idA, "h1", null, ["havoc"]), null, dbgA, null, "h1", 0, DateTimeOffset.UtcNow);
        var ctxB = new ScreamEvolutionBuilder.CrashContext(
            idB, "demo", MakeSidecar(idB, "h2", null, ["havoc"]), null, dbgB, null, "h2", 0, DateTimeOffset.UtcNow);

        Assert.NotEqual(
            ScreamEvolutionBuilder.ComputeFamilyKey(ctxA),
            ScreamEvolutionBuilder.ComputeFamilyKey(ctxB));
    }

    [Fact]
    public void Build_NoDebuggerData_BackwardCompatible()
    {
        var id = Guid.NewGuid();
        var sidecar = MakeSidecar(id, "solo", null, ["havoc"]);
        var ctx = new ScreamEvolutionBuilder.CrashContext(
            id, "demo", sidecar, null, null, null, "solo", 0, DateTimeOffset.UtcNow);

        var evo = ScreamEvolutionBuilder.Build(id, "demo", sidecar, null, null, null, [ctx]);

        Assert.True(evo.Ok);
        Assert.Equal(1, evo.Generation);
        Assert.Equal(1, evo.FamilySize);
        Assert.Equal("stable", evo.MomentumLabel);
    }

    [Fact]
    public void PersistAndRead_RoundTrip()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-evo-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var id = Guid.NewGuid();
        try
        {
            var dto = new ScreamEvolutionDto(
                true, id, "demo", "demo|fam|abc", "fn · seed:corpus", 2,
                Guid.NewGuid(), "parent", 55, "warming",
                ScreamProgressionStep.WriteViolation, ScreamProgressionStep.ReadViolation,
                1, [id], 1, "summary", DateTimeOffset.UtcNow);

            ScreamEvolutionBuilder.Write(dir, dto);
            var read = ScreamEvolutionBuilder.TryRead(ScreamEvolutionBuilder.PathFor(dir, id));

            Assert.NotNull(read);
            Assert.Equal(55, read.MomentumScore);
            Assert.Equal("warming", read.MomentumLabel);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    private static CrashSidecarDto MakeSidecar(Guid id, string hash, string? parent, string[] chain) =>
        new(id, "run", 1, "demo", "cmd", chain[^1], chain, parent, "corpus", [], hash, "x.bin",
            64, -1073741819, "AV", "detail", null, 0, 0, "none", null, null, null, null,
            new TransportSnapshotDto("tcp", "127.0.0.1", 1, false),
            new FuzzSnapshotDto(false, false, "p.yaml"),
            DateTimeOffset.UtcNow);

    private static DebuggerObservation MakeDebugger(
        string fn, DebuggerAccessKind access, string stackHash,
        DebuggerAddressClass addressClass = DebuggerAddressClass.AsciiPattern) =>
        new(true, null, null, null, "AV", access, "0x41414141",
            addressClass, "0x401000", "mod", fn, "+0x10", [],
            stackHash, null, null, null, null, null, null, null, "MEDIUM", "MEDIUM", 0.7,
            "test", 8, false, null, DateTimeOffset.UtcNow);
}
