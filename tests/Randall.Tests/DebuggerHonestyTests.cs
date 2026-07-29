using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

/// <summary>
/// Honesty regressions: null/near-null class, zero-value attribution, R5 gate,
/// CDB marker fault-insn parsing, RIP→symbol, root-cause confidence.
/// Research/teaching only — no exploit payloads.
/// </summary>
public class DebuggerHonestyTests
{
    [Theory]
    [InlineData("0x0", DebuggerAddressClass.NullPage, "NULL")]
    [InlineData("0x00000000", DebuggerAddressClass.NullPage, "NULL")]
    [InlineData("0x1", DebuggerAddressClass.NearNull, "NEAR_NULL")]
    [InlineData("0x100", DebuggerAddressClass.NearNull, "NEAR_NULL")]
    [InlineData("0xFFFF", DebuggerAddressClass.NearNull, "NEAR_NULL")]
    [InlineData("0x41414141", DebuggerAddressClass.AsciiPattern, "PATTERN")]
    public void ClassifyAddress_null_and_near_null_not_heapish(
        string addr, DebuggerAddressClass expected, string label)
    {
        const string heapNoise = """
            00000000`00000000 :
               Region Type: Heap
               HEAP segment clutter
            """;

        Assert.Equal(expected, ScreamInvestigator.ClassifyAddress(addr));
        Assert.Equal(expected, ScreamInvestigator.ClassifyAddress(addr, heapNoise, "HEAP", null));
        Assert.Equal(label, ScreamInvestigator.FormatAddressClass(expected));
    }

    [Theory]
    [InlineData("0x0")]
    [InlineData("0x1")]
    [InlineData("0x2")]
    [InlineData("0x4")]
    [InlineData("0x8")]
    [InlineData("0x10")]
    [InlineData("0xFFFFFFFF")]
    public void MatchRegisterToPayload_excludes_null_and_low_constants(string addr)
    {
        Assert.True(InputAttributionEngine.IsExcludedFromRawInputAttribution(addr));
        var payload = new byte[4096];
        BitConverter.TryWriteBytes(payload.AsSpan(3022), 0u);
        Assert.Null(InputAttributionEngine.MatchRegisterToPayload("rcx", addr, payload));
        Assert.Equal(
            "NULL/low value excluded from raw input-value attribution",
            InputAttributionEngine.LowValueExclusionReason);
    }

    [Fact]
    public void FindRegisterMatches_does_not_claim_rcx_at_zero_padding()
    {
        var payload = new byte[4096];
        var matches = InputAttributionEngine.FindRegisterMatchesFromText(
            payload,
            "rax=0000000000000000 rcx=0000000000000000 rdx=0000000000000001 rip=0000000000401000",
            "0x0",
            "0x401000");
        Assert.Empty(matches);
    }

    [Fact]
    public void Null_write_does_not_claim_controlled_write_or_parser_state_high()
    {
        var sidecar = new CrashSidecarDto(
            Guid.NewGuid(), "run", 1, "vulnserver", "TRUN", "expand",
            ["expand"], null, "seed", [], "hash", "x.bin", 4096,
            -1073741819, "ACCESS_VIOLATION", "detail", null, 0, 0, "native",
            null, null, null, null,
            new TransportSnapshotDto("tcp", "127.0.0.1", 9999, false),
            new FuzzSnapshotDto(false, false, "projects/vulnserver.yaml"),
            DateTimeOffset.UtcNow);

        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: """
                Parameter[0]: 00000001
                Parameter[1]: 00000000
                Attempt to write to address 00000000
                """,
            regs: "rax=0000000000000000 rcx=0000000000000000 rip=00007ff812345678\n",
            address: """
                00000000`00000000 :
                   Region Type: Heap
                """,
            sidecar: sidecar);

        Assert.Equal(DebuggerAccessKind.Write, obs.Access);
        Assert.Equal(DebuggerAddressClass.NullPage, obs.FaultAddressClass);
        Assert.DoesNotContain("Controlled write — register value from input", obs.Diagnosis, StringComparison.Ordinal);
        Assert.Contains("NULL", obs.Diagnosis, StringComparison.Ordinal);

        var analysis = RootCauseEngine.Build(sidecar.CrashId, "vulnserver", sidecar, null, obs, null, null);
        Assert.True(analysis.Ok);
        Assert.NotEqual(RootCauseCategory.ParserState, analysis.Candidate.Category);
        Assert.NotEqual("HIGH", analysis.Candidate.Confidence);
    }

    [Fact]
    public void Null_write_caps_maturity_at_R2_without_control_evidence()
    {
        var id = Guid.NewGuid();
        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Parameter[0]: 00000001\nAttempt to write to address 00000000\n",
            regs: "rcx=0000000000000000 rip=0000000000401000\n");

        var influence = new CrashInfluenceMapDto(
            true, id, "lab", "MEDIUM", "zero coincidence",
            [new InfluenceLinkDto(
                "link-z",
                new InfluenceRegionDto(3022, 3026, 4, null, "boundary", null),
                new InfluencedStateDto(InfluencedStateKind.FaultAddress, "fault", "0x0"),
                InfluenceConfirmationStatus.Observed,
                "pointer→fault address",
                [],
                Honesty: InfluenceHonestyLabel.Observed)],
            [],
            DateTimeOffset.UtcNow);

        var skeptic = new SkepticReportDto(
            true, id, "lab",
            [new SkepticChallengeDto(
                "skep-ok", "claim-1", ResearchClaimKind.InputInfluence,
                "offset influences fault", 75,
                "null: coincidental",
                new HypothesisExperimentDto(HypothesisExperimentKind.MinimizeHold, "neutralize", OffsetBytes: 4),
                "still faults", "clears",
                SkepticChallengeStatus.Survived, 83,
                Observation: "generic survive",
                At: DateTimeOffset.UtcNow)],
            "1 survived",
            DateTimeOffset.UtcNow);

        var report = PrimitiveEngine.Build(id, "lab", influence, null, obs, skeptic: skeptic);
        Assert.True(report.Maturity <= ResearchMaturity.R2);
        Assert.DoesNotContain(report.Primitives, p =>
            p.Kind == PrimitiveKind.InputInfluencedWrite && p.State == PrimitiveState.Observed);
        Assert.DoesNotContain(report.Primitives, p =>
            p.Kind == PrimitiveKind.WriteLengthControl);
    }

    [Fact]
    public void Boundary_null_write_does_not_claim_write_length_or_length_alloc()
    {
        var id = Guid.NewGuid();
        var payload = new byte[64];
        var sidecar = new CrashSidecarDto(
            id, "run", 1, "vulnserver", "TRUN", "boundary",
            ["boundary"], null, "seed", [], "hash", "x.bin", payload.Length,
            -1073741819, "ACCESS_VIOLATION", "detail", null, 0, 0, "native",
            null, null, null, null,
            new TransportSnapshotDto("tcp", "127.0.0.1", 9999, false),
            new FuzzSnapshotDto(false, false, "projects/vulnserver.yaml"),
            DateTimeOffset.UtcNow);

        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Parameter[0]: 00000001\nAttempt to write to address 00000000\n",
            regs: "rcx=0000000000000000 rip=00007ff812345678\n",
            stack: "00000000`0012ff00 00007ff8`12345678 coreclr!SafeExitProcess+0x12",
            symbol: """
                (80000003) BREAKPOINT
                BREAKPOINT_80000003_coreclr.dll!SafeExitProcess+0x12
                (00007ff8`12345678)   coreclr!SafeExitProcess+0x12
                """,
            sidecar: sidecar);

        Assert.Equal("coreclr", obs.FaultingModule);
        Assert.DoesNotContain("BREAKPOINT", obs.FaultingModule ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.Contains("teardown/exit path", obs.FunctionOffset ?? "", StringComparison.OrdinalIgnoreCase);

        var chain = CorruptionChainBuilder.Build(id, "vulnserver", sidecar, obs, null, payload);
        var map = InfluenceEngine.Build(id, "vulnserver", sidecar, null, obs, chain, payload: payload);
        Assert.DoesNotContain(map.Links, l =>
            l.Mechanism.Contains("length→alloc/copy", StringComparison.OrdinalIgnoreCase));

        var report = PrimitiveEngine.Build(id, "vulnserver", map, null, obs, chain);
        Assert.True(report.Maturity <= ResearchMaturity.R2);
        Assert.DoesNotContain(report.Primitives, p => p.Kind == PrimitiveKind.WriteLengthControl);
    }

    [Fact]
    public void MarkerParser_instruction_ignores_Deferred_srv_symbol_path_noise()
    {
        const string golden = """
            Expanded Symbol search path is: srv*C:\Users\007\AppData\Local\Randfuzz\Symbols*https://msdl.microsoft.com/download/symbols
            RANDFUZZ_INSTRUCTION_BEGIN
            Deferred srv*C:\Users\007\AppData\Local\Randfuzz\Symbols*https://msdl.microsoft.com/download/symbols
            00007ff8`12345678 8948d4          mov     dword ptr [rax-2Ch],ecx
            RANDFUZZ_INSTRUCTION_END
            Expanded Symbol search path is: srv*again*
            ===RANDALL_SYMBOL===
            (80000003) BREAKPOINT_80000003
            BREAKPOINT_80000003_coreclr.dll!SafeExitProcess+0x10
            (00007ff8`12345678)   ntdll!RtlpSomething+0x12
            Exact matches:
                ntdll!RtlpSomething (00007ff8`12345600)
            ===RANDALL_SYMBOL_END===
            RANDFUZZ_DISASM_BEGIN
            Deferred srv*should-not-be-fault-insn*
            Expanded Symbol search path is: srv*should-not-be-fault-insn*
            00007ff8`12345678 8948d4          mov     dword ptr [rax-2Ch],ecx
            RANDFUZZ_DISASM_END
            """;

        var transcript = CdbMarkerParser.Parse(golden);
        var insnBlock = transcript.Get(CdbProbeSection.Instruction);
        Assert.Contains("Deferred", insnBlock, StringComparison.OrdinalIgnoreCase);

        var insn = ScreamInvestigator.ExtractFaultInstructionLine(insnBlock, "0x7ff812345678");
        Assert.NotNull(insn);
        Assert.Contains("mov", insn!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("rax-2Ch", insn!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Deferred", insn!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("srv*", insn!, StringComparison.OrdinalIgnoreCase);

        var (fn, mod, off) = ScreamInvestigator.ParseLnSymbol(transcript.Get(CdbProbeSection.Symbol));
        Assert.Equal("ntdll", mod);
        Assert.Equal("RtlpSomething", fn);
        Assert.Equal("+0x12", off);
        Assert.DoesNotContain("BREAKPOINT", mod ?? "", StringComparison.OrdinalIgnoreCase);

        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\nFAULTING_IP: 00007ff812345678\n",
            exr: "Parameter[0]: 00000001\nAttempt to write to address 00000000\n",
            regs: "rip=00007ff812345678 rcx=0000000000000000\n",
            disasm: transcript.Get(CdbProbeSection.Disasm),
            instruction: insnBlock,
            symbol: transcript.Get(CdbProbeSection.Symbol));

        Assert.Equal("RtlpSomething", obs.FaultingFunction);
        Assert.Equal("ntdll", obs.FaultingModule);

        var trace = BackwardTraceBuilder.Build(Guid.NewGuid(), "lab", null, obs, null, null, null);
        Assert.NotNull(trace.FaultInstruction);
        Assert.Contains("mov", trace.FaultInstruction!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Deferred", trace.FaultInstruction!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("srv*", trace.FaultInstruction!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SanitizeModuleName_strips_BREAKPOINT_exception_glue()
    {
        Assert.Equal("coreclr", ScreamInvestigator.SanitizeModuleName("BREAKPOINT_80000003_coreclr.dll"));
        Assert.Equal("vulnserver", ScreamInvestigator.SanitizeModuleName("vulnserver.exe"));
        Assert.Null(ScreamInvestigator.SanitizeModuleName("BREAKPOINT_80000003"));
    }

    [Fact]
    public void All_ones_sentinel_is_unverified_correlation_not_R4()
    {
        var id = Guid.NewGuid();
        var payload = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01 };
        var sidecar = new CrashSidecarDto(
            id, "run", 1, "lab", "TRUN", "boundary",
            ["boundary"], null, "seed", [], "hash", "x.bin", payload.Length,
            -1073741819, "ACCESS_VIOLATION", "detail", null, 0, 0, "native",
            null, null, null, null,
            new TransportSnapshotDto("tcp", "127.0.0.1", 9999, false),
            new FuzzSnapshotDto(false, false, "projects/lab.yaml"),
            DateTimeOffset.UtcNow);

        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005)\n",
            exr: "Attempt to write to address 00000000\nParameter[0]: 00000001\n",
            regs: "rcx=ffffffffffffffff rax=0000000000000000 rip=0000000000401000\n",
            sidecar: sidecar);

        var map = InfluenceEngine.Build(id, "lab", sidecar, null, obs, null, payload: payload);
        Assert.Contains(map.Links, l =>
            (l.Mechanism.Contains("Observed Association", StringComparison.OrdinalIgnoreCase)
             || l.Mechanism.Contains("co-occurs", StringComparison.OrdinalIgnoreCase))
            && l.Honesty == InfluenceHonestyLabel.Unverified);

        var report = PrimitiveEngine.Build(id, "lab", map, null, obs);
        Assert.True(report.Maturity <= ResearchMaturity.R2);
        Assert.DoesNotContain(report.Primitives, p => p.Kind == PrimitiveKind.WriteLengthControl);
    }

    [Fact]
    public void StandardCrash_script_includes_instruction_and_symbol_markers()
    {
        var script = CdbScriptBuilder.BuildInline(CdbProbePlan.StandardCrash);
        Assert.Contains("u @rip L1", script, StringComparison.Ordinal);
        Assert.Contains("ln @rip", script, StringComparison.Ordinal);
        Assert.Contains(CdbMarkers.Begin(CdbProbeSection.Instruction), script, StringComparison.Ordinal);
        Assert.Contains(CdbMarkers.Begin(CdbProbeSection.Symbol), script, StringComparison.Ordinal);
    }

    [Fact]
    public void PageHeap_text_alone_is_not_uaf_signal()
    {
        Assert.False(ScreamInvestigator.HasExplicitUafIndicator("Page Heap fingerprints detected\n!heap -p\nhpa enabled"));
        Assert.True(ScreamInvestigator.HasExplicitUafIndicator("use after free detected in block"));
    }

    [Fact]
    public void Narrative_null_write_does_not_claim_controlled_write_in_junk_symbol()
    {
        var sidecar = new CrashSidecarDto(
            Guid.NewGuid(), "run", 1, "vulnserver", "KSTET", "havoc",
            ["havoc"], null, "seed", [], "hash", "x.bin", 128,
            -1073741819, "ACCESS_VIOLATION", "detail", null, 0, 0, "native",
            null, null, null, null,
            new TransportSnapshotDto("tcp", "127.0.0.1", 9999, false),
            new FuzzSnapshotDto(false, false, "projects/vulnserver.yaml"),
            DateTimeOffset.UtcNow);

        var obs = new DebuggerObservation(
            Ok: true,
            DumpPath: null,
            ObservationPath: null,
            ExceptionCode: "0xC0000005",
            ExceptionHint: "ACCESS_VIOLATION",
            Access: DebuggerAccessKind.Write,
            FaultAddress: "0x0",
            FaultAddressClass: DebuggerAddressClass.NullPage,
            Rip: "0x401000",
            FaultingModule: "!",
            FaultingFunction: ":",
            FunctionOffset: null,
            Stack: [],
            StackHash: null,
            RegistersText: "rdi=0000000000000000 rip=0000000000401000",
            DisasmNearRip: null,
            MemoryNearRsp: null,
            ModulesText: null,
            HeapProbeText: null,
            AddressQueryText: null,
            ExrText: null,
            ExploitableClassification: null,
            ExploitableDescription: null,
            HeapSignal: null,
            SuspectedInputInfluence: "MEDIUM",
            ExploitabilityHint: "UNKNOWN",
            Confidence: 0.5,
            Diagnosis: "Write AV",
            DebuggerScreamBonus: 0,
            AnalyzeTimedOut: false,
            Error: null,
            At: DateTimeOffset.UtcNow);

        var narrative = InputAttributionEngine.BuildNarrative(
            sidecar, obs, primary: null, depth: 77, mutator: "havoc", mutStep: 0, mutNote: null, matches: []);
        Assert.NotNull(narrative);
        Assert.DoesNotContain("controlled write", narrative!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("!:", narrative!, StringComparison.Ordinal);
        Assert.Contains("null/invalid destination write", narrative!, StringComparison.OrdinalIgnoreCase);
    }
}
