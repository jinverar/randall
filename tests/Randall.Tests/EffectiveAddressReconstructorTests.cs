using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class EffectiveAddressReconstructorTests
{
    [Fact]
    public void Reconstruct_MovDwordPtrRaxMinus2Ch_ComputesEaAndValue()
    {
        const string insn = "00007ff6`12340100 8948d4  mov dword ptr [rax-2Ch],ecx";
        const string regs = """
            rax=0000000000010000
            rcx=00000000DEADBEEF
            rip=00007ff612340100
            """;

        var ea = EffectiveAddressReconstructor.Reconstruct(insn, regs, preferRip: "00007ff612340100");

        Assert.True(ea.Ok);
        Assert.Equal("mov", ea.Mnemonic);
        Assert.Equal("dword", ea.WidthLabel);
        Assert.Equal(4, ea.WidthBytes);
        Assert.Equal("rax", ea.BaseRegister);
        Assert.Null(ea.IndexRegister);
        Assert.Equal(-0x2C, ea.Displacement);
        Assert.Equal("ecx", ea.SourceRegister);
        Assert.Equal("0xFFD4", ea.EffectiveAddressHex); // 0x10000 - 0x2C
        Assert.Equal("0xDEADBEEF", ea.ValueHex);
        Assert.Equal("Write", ea.AccessKind);
        Assert.Equal(nameof(ExploitClaimKind.Observed), ea.Honesty);
        Assert.Equal("Static", ea.ReconstructionKind);
    }

    [Fact]
    public void Reconstruct_IndexedOperand_AppliesScale()
    {
        const string insn = "mov qword ptr [rbx+rcx*8+10h],rax";
        const string regs = """
            rbx=0000000000001000
            rcx=0000000000000002
            rax=0000000011223344
            """;

        var ea = EffectiveAddressReconstructor.Reconstruct(insn, regs);

        Assert.True(ea.Ok);
        Assert.Equal("rbx", ea.BaseRegister);
        Assert.Equal("rcx", ea.IndexRegister);
        Assert.Equal(8, ea.Scale);
        Assert.Equal(0x10, ea.Displacement);
        // 0x1000 + 2*8 + 0x10 = 0x1020
        Assert.Equal("0x1020", ea.EffectiveAddressHex);
        Assert.Equal(8, ea.WidthBytes);
    }

    [Fact]
    public void Panel_NeverPromotesCoincidenceToConfirmed()
    {
        var dbg = new DebuggerObservation(
            Ok: true,
            DumpPath: null,
            ObservationPath: null,
            ExceptionCode: "c0000005",
            ExceptionHint: "ACCESS_VIOLATION",
            Access: DebuggerAccessKind.Write,
            FaultAddress: "0xFFF4",
            FaultAddressClass: DebuggerAddressClass.SmallOffset,
            Rip: "0x100",
            FaultingModule: "demo",
            FaultingFunction: "write_it",
            FunctionOffset: "+0x10",
            Stack: [],
            StackHash: null,
            RegistersText: "rax=0000000000010000 rcx=00000000AABBCCDD",
            DisasmNearRip: "mov dword ptr [rax-2Ch],ecx",
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
            Diagnosis: "test",
            DebuggerScreamBonus: 0,
            AnalyzeTimedOut: false,
            Error: null,
            At: DateTimeOffset.UtcNow,
            RegisterMatches:
            [
                new RegisterPayloadMatchDto("RCX", "0xAABBCCDD", 40, 4, "dword", "coincidence"),
            ]);

        var panel = ExploitResearchPanelBuilder.Build(
            Guid.NewGuid(), "demo", dbg, influence: null, primitives: null,
            counterfactual: null, plan: null, skeptic: null);

        Assert.True(panel.Ok);
        Assert.NotNull(panel.EffectiveAddress);
        Assert.Equal("0xFFD4", panel.EffectiveAddress!.EffectiveAddressHex);
        var rcx = Assert.Single(panel.RegisterMatrix, r => r.Register is "RCX" or "ECX");
        Assert.True(rcx.Status is InputControlStatus.Correlated or InputControlStatus.Influenced);
        Assert.NotEqual(InputControlStatus.Confirmed, rcx.Status);
        Assert.Contains("destination", panel.WriteControl!.DestinationControl, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("value", panel.WriteControl.ValueControl, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(panel.Engine);
        Assert.False(string.IsNullOrWhiteSpace(panel.Engine!.Version));
    }
}
