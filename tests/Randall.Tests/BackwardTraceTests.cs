using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class BackwardTraceTests
{
    [Fact]
    public void Build_ascii_write_av_produces_high_confidence_story()
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

        Assert.True(trace.Ok);
        Assert.Equal("HIGH", trace.Confidence);
        Assert.Contains("expand", trace.Story, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("41414141", trace.Story, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(trace.Steps, s => s.Kind == "mutation");
        Assert.Contains(trace.Steps, s => s.Kind == "register");
        Assert.Contains(trace.Steps, s => s.Kind == "crash");
        Assert.NotNull(trace.FaultInstruction);
        Assert.Equal("RAX", trace.FaultRegister);
        Assert.Contains(trace.RegisterMatches ?? [], m => m.Register == "FAULT");
    }

    [Fact]
    public void Build_heap_uaf_timeline_when_freed_class()
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

        Assert.True(trace.Ok);
        Assert.NotNull(trace.HeapTimeline);
        Assert.Contains("freed", trace.HeapTimeline!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(trace.Steps, s => s.Kind == "heap-timeline");
        Assert.Contains(trace.Steps, s => s.Kind == "source");
    }

    [Fact]
    public void PersistForCrash_writes_json_sidecar()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randfuzz-btrace-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            var obs = ScreamInvestigator.ParseBlocks(
                "EXCEPTION_CODE: (c0000005)\n",
                exr: "Attempt to write to address 41414141\n",
                regs: "rip=0000000041414141\n");

            var trace = BackwardTraceBuilder.PersistForCrash(
                dir, id, "lab", null, obs, null, null, null);

            var path = BackwardTraceBuilder.PathFor(dir, id);
            Assert.True(File.Exists(path));
            var loaded = BackwardTraceBuilder.TryRead(path);
            Assert.NotNull(loaded);
            Assert.Equal(trace.Story, loaded!.Story);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }
}
