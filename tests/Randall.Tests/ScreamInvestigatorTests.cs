using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class ScreamInvestigatorTests
{
    [Fact]
    public void ClassifyAddress_detects_ascii_and_null()
    {
        Assert.Equal(DebuggerAddressClass.AsciiPattern, ScreamInvestigator.ClassifyAddress("0x41414141"));
        Assert.Equal(DebuggerAddressClass.NullPage, ScreamInvestigator.ClassifyAddress("0x0"));
        Assert.Equal(DebuggerAddressClass.NearNull, ScreamInvestigator.ClassifyAddress("0x2000"));
        Assert.Equal(DebuggerAddressClass.NearNull, ScreamInvestigator.ClassifyAddress("0x1"));
        Assert.Equal(DebuggerAddressClass.Unknown, ScreamInvestigator.ClassifyAddress("0x????????"));
    }

    [Fact]
    public void ClassifyAddress_uses_address_heap_and_lm_probes()
    {
        const string stackQuery = """
            00000000`0012ff00 :
               Region Type: Stack
            """;
        Assert.Equal(DebuggerAddressClass.Stackish,
            ScreamInvestigator.ClassifyAddress("0x12ff00", stackQuery, null, null));

        const string freedQuery = """
            000001a2`3b4c5000 :
               Free memory
            """;
        Assert.Equal(DebuggerAddressClass.Freed,
            ScreamInvestigator.ClassifyAddress("0x1a23b4c5000", freedQuery, null, null));

        const string lm = """
            start             end               module name
            00007ff6`12340000 00007ff6`12380000 vulnserver
            """;
        Assert.Equal(DebuggerAddressClass.ModuleRange,
            ScreamInvestigator.ClassifyAddress("0x7ff612345678", null, null, lm));
    }

    [Theory]
    [InlineData("Parameter[0]: 00000000", DebuggerAccessKind.Read)]
    [InlineData("Parameter[0]: 00000001", DebuggerAccessKind.Write)]
    [InlineData("Parameter[0]: 00000008", DebuggerAccessKind.Execute)]
    public void InferAccess_reads_exception_parameters(string exr, DebuggerAccessKind expected) =>
        Assert.Equal(expected, ScreamInvestigator.InferAccess(exr, ""));

    [Fact]
    public void ParseBlocks_builds_diagnosis_and_write_av()
    {
        const string analyze = """
            EXCEPTION_CODE: (c0000005) Access violation
            FAULTING_IP: 004020e2
            FAULTING_MODULE: randall-vulndrone.exe
            """;
        const string exr = """
            ExceptionAddress: 004020e2
            ExceptionCode: c0000005 (Access violation)
            ExceptionFlags: 00000000
            NumberParameters: 2
            Parameter[0]: 00000001
            Parameter[1]: 41414141
            Attempt to write to address 41414141
            """;
        const string regs = """
            rax=0000000041414141 rbx=0000000000000000 rcx=000000007fffffff
            rip=00000000004020e2 rsp=000000000012ff00
            """;
        const string stack = """
            Child-SP              RetAddr               Call Site
            00000000`0012ff00     00000000`00401000     randall_vulndrone!HandleHello+0x42
            00000000`0012ff80     00000000`00400100     randall_vulndrone!TcpServe+0x10
            """;

        var sidecar = new CrashSidecarDto(
            Guid.NewGuid(), "run", 12, "vulndrone-tcp", "HELLO", "expand",
            ["expand"], null, "seed", [], "DEADBEEF", "x.bin", 963,
            -1073741819, "ACCESS_VIOLATION", "server exited", null, 0, 0, "native",
            null, null, null, null,
            new TransportSnapshotDto("tcp", "127.0.0.1", 15551, false),
            new FuzzSnapshotDto(false, false, "projects/vulndrone-tcp.yaml"),
            DateTimeOffset.UtcNow);

        var obs = ScreamInvestigator.ParseBlocks(analyze, exr, regs, stack, sidecar: sidecar);

        Assert.True(obs.Ok);
        Assert.Equal(DebuggerAccessKind.Write, obs.Access);
        Assert.Equal(DebuggerAddressClass.AsciiPattern, obs.FaultAddressClass);
        Assert.Equal("HIGH", obs.SuspectedInputInfluence);
        Assert.Equal("HIGH", obs.ExploitabilityHint);
        Assert.Contains("HandleHello", obs.FaultingFunction!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Write", obs.Diagnosis, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("HELLO", obs.Diagnosis, StringComparison.OrdinalIgnoreCase);
        Assert.True(obs.DebuggerScreamBonus >= 10);
        Assert.False(string.IsNullOrWhiteSpace(obs.StackHash));
    }

    [Fact]
    public void PersistFromCdbBlocks_writes_json()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randfuzz-investigator-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            var obs = ScreamInvestigator.PersistFromCdbBlocks(
                dir, id, "fake.dmp",
                "EXCEPTION_CODE: (c0000005) Access violation\nFAULTING_IP: 41414141\n",
                "Attempt to write to address 41414141\n",
                "rip=0000000041414141\n",
                "",
                "",
                "",
                "",
                "",
                "",
                "Exploitability Classification: EXPLOITABLE\n",
                false,
                null);

            Assert.True(File.Exists(ScreamInvestigator.ObservationPathFor(dir, id)));
            var loaded = ScreamInvestigator.TryRead(ScreamInvestigator.ObservationPathFor(dir, id));
            Assert.NotNull(loaded);
            Assert.Equal(obs.Diagnosis, loaded!.Diagnosis);
            Assert.Equal("EXPLOITABLE", loaded.ExploitableClassification);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }
}
