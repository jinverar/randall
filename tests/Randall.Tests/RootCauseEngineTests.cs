using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class RootCauseEngineTests
{
    [Fact]
    public void Build_ascii_write_av_classifies_bounds_violation_with_high_confidence()
    {
        var id = Guid.NewGuid();
        var payload = new byte[64];
        BitConverter.TryWriteBytes(payload.AsSpan(40), 0x41414141u);

        var sidecar = new CrashSidecarDto(
            id, "run", 3, "lab", "HELLO", "expand",
            ["bitflip", "expand"], null, "seed", [], "DEADBEEF", "x.bin", payload.Length,
            -1073741819, "ACCESS_VIOLATION", "detail", null, 0, 0, "native",
            null, null, null, null,
            new TransportSnapshotDto("tcp", "127.0.0.1", 9999, false),
            new FuzzSnapshotDto(false, false, "projects/lab.yaml"),
            DateTimeOffset.UtcNow);

        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Attempt to write to address 41414141\nParameter[1]: 41414141\n",
            regs: "rax=0000000041414141\nrip=00000000401020\n",
            stack: "00000000`0012ff00 00000000`00401000 lab!Parse+0x10",
            disasm: "00401020  mov dword ptr [rax], ecx",
            sidecar: sidecar);

        var triage = CrashTriage.Classify(null, sidecar, null, payload, debugger: obs);
        var chain = CorruptionChainBuilder.Build(id, "lab", sidecar, obs, triage, payload);
        var trace = BackwardTraceBuilder.Build(id, "lab", sidecar, obs, triage, chain, payload);
        var analysis = RootCauseEngine.Build(id, "lab", sidecar, triage, obs, chain, trace);

        Assert.True(analysis.Ok);
        Assert.Equal(RootCauseCategory.BoundsViolation, analysis.Candidate.Category);
        Assert.Equal("HIGH", analysis.Candidate.Confidence);
        Assert.Contains(analysis.Candidate.Evidence, f => f.Source == "debugger");
        Assert.Contains(analysis.Candidate.Evidence, f => f.Source == "corruption_chain");
        Assert.NotNull(analysis.Candidate.InputRegion);
        Assert.Contains("41414141", analysis.EducationalSummary, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(analysis.Candidate.Inferences, i =>
            i.Contains("out-of-bounds", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Build_heap_uaf_classifies_lifetime_violation()
    {
        var id = Guid.NewGuid();
        const string addressQuery = """
            000001a2`3b4c5000 :
               Free memory
            """;
        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Attempt to read from address 000001a23b4c5000\n",
            regs: "rcx=000001a23b4c5000\nrip=00007ff612345678\n",
            address: addressQuery,
            heap: "use after free detected");

        var trace = BackwardTraceBuilder.Build(id, "lab", null, obs, null, null, null);
        var analysis = RootCauseEngine.Build(id, "lab", null, null, obs, null, trace);

        Assert.True(analysis.Ok);
        Assert.Equal(RootCauseCategory.LifetimeViolation, analysis.Candidate.Category);
        Assert.Contains(analysis.Candidate.ObservedFacts, f =>
            f.Contains("use after free", StringComparison.OrdinalIgnoreCase)
            || f.Contains("Free memory", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("Lifetime violation", analysis.EducationalSummary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CollectEvidenceFacts_includes_ghidra_static_when_present()
    {
        var triage = new CrashTriageDto(
            Class: "ACCESS_VIOLATION",
            Severity: "high",
            Summary: "summary",
            IpLooksControlled: false,
            StackLooksSmashed: false,
            ClusterKey: "test",
            ExceptionHint: null,
            FaultAddress: null,
            FaultModule: null,
            Rip: null,
            Rsp: null,
            StaticFunction: new StaticFunctionMappingDto(
                PcSource: "rip",
                PcAddress: "0x401020",
                FunctionName: "handle_request",
                Offset: "+0xA",
                Source: "ghidra",
                InstructionHint: "CALL memcpy"));

        var facts = RootCauseEngine.CollectEvidenceFacts(null, triage, null, null, null, null);

        Assert.Contains(facts, f => f.Source == "ghidra" && f.Value != null && f.Value.Contains("handle_request"));
        Assert.Contains(facts, f => f.Source == "ghidra" && f.Value != null && f.Value.Contains("memcpy"));
    }

    [Fact]
    public void PersistForCrash_writes_json_sidecar()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randfuzz-rca-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            var obs = ScreamInvestigator.ParseBlocks(
                "EXCEPTION_CODE: (c0000005)\n",
                exr: "Attempt to write to address 41414141\n",
                regs: "rip=0000000041414141\n");

            var analysis = RootCauseEngine.PersistForCrash(
                dir, id, "lab", null, null, obs, null, null);

            var path = RootCauseEngine.PathFor(dir, id);
            Assert.True(File.Exists(path));
            var loaded = RootCauseEngine.TryRead(path);
            Assert.NotNull(loaded);
            Assert.Equal(analysis.Candidate.Category, loaded!.Candidate.Category);
            Assert.Equal(analysis.EducationalSummary, loaded.EducationalSummary);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Build_insufficient_evidence_returns_ok_false()
    {
        var id = Guid.NewGuid();
        var analysis = RootCauseEngine.Build(id, "lab", null, null, null, null, null);

        Assert.False(analysis.Ok);
        Assert.Equal(RootCauseCategory.Unknown, analysis.Candidate.Category);
        Assert.Contains("Insufficient evidence", analysis.EducationalSummary);
    }
}
