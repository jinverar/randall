using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class EffectiveAddressReconstructorTests
{
    [Fact]
    public void Reconstruct_MovDwordPtrRaxMinus2Ch_NullPage_ComputesEaZero()
    {
        // Classic null-page write: RAX = 0x2C → [rax-2Ch] = 0
        const string insn = "00007ff6`12340100 8948d4  mov dword ptr [rax-2Ch],ecx";
        const string regs = """
            rax=000000000000002C
            rcx=00000000DEADBEEF
            rip=00007ff612340100
            """;

        var ea = EffectiveAddressReconstructor.Reconstruct(
            insn, regs, preferRip: "00007ff612340100", faultAddress: "0x0");

        Assert.True(ea.Ok);
        Assert.Equal("mov", ea.Mnemonic);
        Assert.Equal("dword", ea.WidthLabel);
        Assert.Equal(4, ea.WidthBytes);
        Assert.Equal("rax", ea.BaseRegister);
        Assert.Null(ea.IndexRegister);
        Assert.Equal(-0x2C, ea.Displacement);
        Assert.Equal("ecx", ea.SourceRegister);
        Assert.Equal("0x0", ea.EffectiveAddressHex);
        Assert.Equal("0xDEADBEEF", ea.ValueHex);
        Assert.Equal("Write", ea.AccessKind);
        Assert.Equal("rax + (-0x2C)", ea.Expression);
        Assert.True(ea.MatchesFaultAddress);
        Assert.Equal("0x0", ea.FaultAddressHex);
        Assert.Equal(nameof(ExploitClaimKind.Observed), ea.Honesty);
        Assert.Equal("Static", ea.ReconstructionKind);
    }

    [Fact]
    public void Reconstruct_MovDwordPtrRaxMinus2Ch_NonNull_ComputesEaAndValue()
    {
        const string insn = "00007ff6`12340100 8948d4  mov dword ptr [rax-2Ch],ecx";
        const string regs = """
            rax=0000000000010000
            rcx=00000000DEADBEEF
            rip=00007ff612340100
            """;

        var ea = EffectiveAddressReconstructor.Reconstruct(insn, regs, preferRip: "00007ff612340100");

        Assert.True(ea.Ok);
        Assert.Equal("0xFFD4", ea.EffectiveAddressHex); // 0x10000 - 0x2C
        Assert.Equal("0xDEADBEEF", ea.ValueHex);
        Assert.Null(ea.MatchesFaultAddress);
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
        Assert.Equal("rbx + rcx*8 + 0x10", ea.Expression);
        Assert.Equal(8, ea.WidthBytes);
        Assert.Equal("0x11223344", ea.ValueHex);
    }

    [Fact]
    public void Reconstruct_IndexOnlyScaled_ComputesEa()
    {
        const string insn = "mov eax,dword ptr [rcx*4+20h]";
        const string regs = """
            rcx=0000000000000010
            rax=0000000000000000
            """;

        var ea = EffectiveAddressReconstructor.Reconstruct(insn, regs);

        Assert.True(ea.Ok);
        Assert.Null(ea.BaseRegister);
        Assert.Equal("rcx", ea.IndexRegister);
        Assert.Equal(4, ea.Scale);
        Assert.Equal(0x20, ea.Displacement);
        // 0x10*4 + 0x20 = 0x60
        Assert.Equal("0x60", ea.EffectiveAddressHex);
        Assert.Equal("rcx*4 + 0x20", ea.Expression);
    }

    [Fact]
    public void Reconstruct_RipRelative_UsesInsnLength()
    {
        // 8B 05 xx xx xx xx = mov eax, dword ptr [rip+disp32] (6 bytes)
        const string insn = "00007ff612340100 8b0512340000  mov eax,dword ptr [rip+1234h]";
        const string regs = """
            rip=00007ff612340100
            rax=0000000000000000
            """;

        var ea = EffectiveAddressReconstructor.Reconstruct(insn, regs, preferRip: "00007ff612340100");

        Assert.True(ea.Ok);
        Assert.Equal("rip", ea.BaseRegister);
        Assert.Equal(0x1234, ea.Displacement);
        Assert.Equal(6, EffectiveAddressReconstructor.TryInsnByteLength(insn));
        // RIP + insnLen(6) + 0x1234 = 0x7FF612340100 + 6 + 0x1234 = 0x7FF61234133A
        Assert.Equal("0x7FF61234133A", ea.EffectiveAddressHex);
    }

    [Fact]
    public void Reconstruct_SymbolPathNoise_ReturnsUnknownHonestly()
    {
        const string noise = """
            Expanded Symbol search path is: srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
            Deferred srv*C:\Symbols*
            """;

        var ea = EffectiveAddressReconstructor.Reconstruct(noise, "rax=1", faultAddress: "0x0");

        Assert.False(ea.Ok);
        Assert.Null(ea.Instruction);
        Assert.Null(ea.EffectiveAddressHex);
        Assert.Equal(nameof(ExploitClaimKind.Unverified), ea.Honesty);
        Assert.Contains("UNKNOWN", ea.Note, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("srv*", ea.Instruction ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public void Reconstruct_EaMismatch_FlagsFaultCompare()
    {
        const string insn = "mov dword ptr [rax],ecx";
        const string regs = "rax=0000000000001000 rcx=00000000AABBCCDD";

        var ea = EffectiveAddressReconstructor.Reconstruct(insn, regs, faultAddress: "0x2000");

        Assert.True(ea.Ok);
        Assert.Equal("0x1000", ea.EffectiveAddressHex);
        Assert.False(ea.MatchesFaultAddress);
        Assert.Contains("≠ fault", ea.Note, StringComparison.Ordinal);
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
            FaultAddress: "0x0",
            FaultAddressClass: DebuggerAddressClass.NullPage,
            Rip: "0x100",
            FaultingModule: "demo",
            FaultingFunction: "write_it",
            FunctionOffset: "+0x10",
            Stack: [],
            StackHash: null,
            RegistersText: "rax=000000000000002C rcx=00000000AABBCCDD",
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
        Assert.Equal("0x0", panel.EffectiveAddress!.EffectiveAddressHex);
        Assert.True(panel.EffectiveAddress.MatchesFaultAddress);
        Assert.Equal("0xAABBCCDD", panel.CausingValue);
        Assert.DoesNotContain("srv*", panel.FaultInstruction ?? "", StringComparison.OrdinalIgnoreCase);
        var rcx = Assert.Single(panel.RegisterMatrix, r => r.Register is "RCX" or "ECX");
        Assert.True(rcx.Status is InputControlStatus.Correlated or InputControlStatus.Influenced);
        Assert.NotEqual(InputControlStatus.Confirmed, rcx.Status);
        Assert.Contains("destination", panel.WriteControl!.DestinationControl, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("value", panel.WriteControl.ValueControl, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(panel.Engine);
        Assert.False(string.IsNullOrWhiteSpace(panel.Engine!.Version));
    }

    [Fact]
    public void Panel_PersistsUnknownWhenNoDisasm()
    {
        var panel = ExploitResearchPanelBuilder.Build(
            Guid.NewGuid(), "demo", debugger: null, influence: null, primitives: null,
            counterfactual: null, plan: null, skeptic: null);

        Assert.Equal("UNKNOWN", panel.FaultInstruction);
        Assert.NotNull(panel.EffectiveAddress);
        Assert.False(panel.EffectiveAddress!.Ok);
        Assert.Equal("UNKNOWN", panel.CausingAddress);
        Assert.Equal("UNKNOWN", panel.CausingValue);
        Assert.NotNull(panel.Engine);
    }
}
