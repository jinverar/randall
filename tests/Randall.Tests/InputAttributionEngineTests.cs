using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class InputAttributionEngineTests
{
    [Fact]
    public void FindRegisterMatches_finds_ascii_dword_in_payload()
    {
        var payload = new byte[64];
        BitConverter.TryWriteBytes(payload.AsSpan(20), 0x41414141u);

        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005)\n",
            exr: "Attempt to write to address 41414141\n",
            regs: "rax=0000000041414141\n");

        var matches = InputAttributionEngine.FindRegisterMatches(payload, obs, null);

        Assert.NotEmpty(matches);
        Assert.Contains(matches, m => m.Register == "RAX" && m.PayloadOffset == 20 && m.MatchKind == "ascii");
    }

    [Fact]
    public void FindRegisterMatches_correlates_fault_and_rcx()
    {
        var payload = new byte[64];
        BitConverter.TryWriteBytes(payload.AsSpan(8), 0x41414141u);
        BitConverter.TryWriteBytes(payload.AsSpan(32), 0x7FFFFFFFu);

        var matches = InputAttributionEngine.FindRegisterMatchesFromText(
            payload,
            "rax=0000000041414141 rcx=000000007fffffff rip=00000000004020e2",
            "0x41414141",
            "0x4020e2");

        Assert.Contains(matches, m => m.Register == "RCX" && m.PayloadOffset == 32);
        Assert.Contains(matches, m => m.Register == "FAULT" && m.PayloadOffset == 8);
    }

    [Fact]
    public void Analyze_attributes_expand_for_tail_ascii_fault()
    {
        var payload = new byte[80];
        BitConverter.TryWriteBytes(payload.AsSpan(60), 0x42424242u);
        var lineage = new List<string> { "bitflip", "expand", "havoc" };

        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005)\n",
            exr: "Attempt to write to address 42424242\n",
            regs: "rdx=0000000042424242\n",
            stack: "00000000`0012ff00 00000000`00401000 lab!memcpy+0x12");

        var result = InputAttributionEngine.Analyze(payload, obs, null, null, lineage);

        Assert.Equal("expand", result.SuspectedMutator);
        Assert.Equal(1, result.SuspectedMutatorStep);
        Assert.Equal("HIGH", result.Confidence);
        Assert.True(result.AttributionScreamBonus >= 6);
        Assert.NotNull(result.Narrative);
        Assert.Contains("42424242", result.Narrative!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("memcpy", result.Narrative!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FindPatternDepth_checks_general_purpose_registers()
    {
        var payload = new byte[32];
        BitConverter.TryWriteBytes(payload.AsSpan(12), 0xDEADBEEFu);
        var regs = "rdx=00000000deadbeef\n";

        var (depth, note) = CrashTriage.FindPatternDepth(payload, null, null, null, regs);

        Assert.Equal(12, depth);
        Assert.Contains("RDX", note!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BuildNarrative_chains_field_register_sink_av()
    {
        var sidecar = new CrashSidecarDto(
            Guid.NewGuid(), "run", 1, "lab", "HELLO", "expand", ["expand"], null, "seed", [],
            "hash", "x.bin", 64, -1073741819, "AV", "detail", null, 0, 0, "native",
            null, null, null, null,
            new TransportSnapshotDto("tcp", "127.0.0.1", 9999, false),
            new FuzzSnapshotDto(false, false, "projects/lab.yaml"),
            DateTimeOffset.UtcNow);

        var debugger = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Attempt to write to address 41414141\n",
            regs: "rax=0000000041414141\n",
            stack: "00000000`0012ff00 00000000`00401000 lab!HandleHello+0x42");

        var match = new RegisterPayloadMatchDto("RAX", "0x41414141", 20, 4, "ascii", "test");
        var narrative = InputAttributionEngine.BuildNarrative(
            sidecar, debugger, match, 20, "expand", 0, "ASCII fault", [match]);

        Assert.NotNull(narrative);
        Assert.Contains("HELLO", narrative!);
        Assert.Contains("RAX", narrative!);
        Assert.Contains("write AV", narrative!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("expand", narrative!);
    }
}
