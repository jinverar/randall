using Randall.Contracts;
using Randall.Infrastructure;

namespace Randall.Tests.ResearchBenchmark;

/// <summary>
/// Teaching-bug catalog for the research accuracy benchmark.
/// Live = ParseBlocks / engine wired with expected envelope; Stub = TODO.
/// </summary>
public static class ResearchBenchmarkFixtures
{
    public static IReadOnlyList<ResearchBenchmarkEnvelope> All { get; } =
    [
        new(
            "null-deref",
            "null-deref",
            Stub: false,
            ExpectCrashDetection: true,
            ExpectedAccess: DebuggerAccessKind.Write,
            ExpectedAddressClass: DebuggerAddressClass.NullPage,
            ExpectedPcContains: "401020",
            AllowedRootFamilies: [RootCauseCategory.UnexpectedObjectState, RootCauseCategory.BoundsViolation, RootCauseCategory.Uninitialized, RootCauseCategory.Unknown],
            MaxMaturityWithoutPromotion: ResearchMaturity.R4,
            Notes: "Null-page write — debugger-corpus null-deref"),

        new(
            "ascii-write",
            "stack-overwrite",
            Stub: false,
            ExpectCrashDetection: true,
            ExpectedAccess: DebuggerAccessKind.Write,
            ExpectedAddressClass: DebuggerAddressClass.AsciiPattern,
            ExpectedPcContains: "401020",
            AllowedRootFamilies: [RootCauseCategory.BoundsViolation, RootCauseCategory.UnexpectedObjectState, RootCauseCategory.Unknown],
            MaxMaturityWithoutPromotion: ResearchMaturity.R4,
            Notes: "ASCII-controlled write addr — teaching stand-in for stack/pattern overwrite"),

        new(
            "av-read",
            "null-deref",
            Stub: false,
            ExpectCrashDetection: true,
            ExpectedAccess: DebuggerAccessKind.Read,
            ExpectedAddressClass: DebuggerAddressClass.AsciiPattern,
            ExpectedPcContains: "401020",
            AllowedRootFamilies: [RootCauseCategory.BoundsViolation, RootCauseCategory.UnexpectedObjectState, RootCauseCategory.Unknown],
            MaxMaturityWithoutPromotion: ResearchMaturity.R4,
            Notes: "Wild/ASCII read AV"),

        new(
            "oob-write",
            "oob-write",
            Stub: true,
            ExpectCrashDetection: true,
            ExpectedAccess: DebuggerAccessKind.Write,
            ExpectedAddressClass: DebuggerAddressClass.Heapish,
            Notes: "TODO: wire managed/native OOB write envelope"),

        new(
            "integer-trunc",
            "integer-boundary",
            Stub: true,
            ExpectCrashDetection: true,
            AllowedRootFamilies: [RootCauseCategory.IntegerConversion, RootCauseCategory.SizeMismatch, RootCauseCategory.Unknown],
            Notes: "TODO: integer/boundary length fixture"),

        new(
            "uaf",
            "uaf",
            Stub: true,
            ExpectCrashDetection: true,
            ExpectedAddressClass: DebuggerAddressClass.Freed,
            AllowedRootFamilies: [RootCauseCategory.LifetimeViolation, RootCauseCategory.UnexpectedObjectState, RootCauseCategory.Unknown],
            Notes: "TODO: UAF lab envelope when harness is live"),

        new(
            "stack-corrupt",
            "stack-overwrite",
            Stub: true,
            ExpectCrashDetection: true,
            ExpectedAccess: DebuggerAccessKind.Write,
            ExpectedAddressClass: DebuggerAddressClass.Stackish,
            Notes: "TODO: stack smash managed fixture"),

        new(
            "oracle-silent",
            "oracle-silent",
            Stub: true,
            ExpectCrashDetection: true,
            Notes: "TODO: silent scream / oracle-only envelope (no memory crash)"),
    ];

    public static IEnumerable<ResearchBenchmarkEnvelope> Live => All.Where(f => !f.Stub);
    public static IEnumerable<ResearchBenchmarkEnvelope> Stubs => All.Where(f => f.Stub);

    /// <summary>Build a debugger observation for a live fixture (ParseBlocks — no lab TCP).</summary>
    public static DebuggerObservation BuildObservation(ResearchBenchmarkEnvelope env) => env.FixtureId switch
    {
        "null-deref" => ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Attempt to write to address 0000000000000000\nParameter[1]: 0000000000000000\n",
            regs: "rax=0000000000000000\nrip=0000000000401020\n",
            stack: "00000000`0012ff00 00000000`00401000 lab!WriteNull+0x10",
            disasm: "00401020  mov dword ptr [rax], ecx",
            address: "Null page"),

        "ascii-write" => ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Attempt to write to address 41414141\nParameter[1]: 41414141\n",
            regs: "rax=0000000041414141\nrip=0000000000401020\n",
            stack: "00000000`0012ff00 00000000`00414141 lab!Parse+0x10",
            disasm: "00401020  mov dword ptr [rax], ecx"),

        "av-read" => ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Attempt to read from address 41414141\nParameter[1]: 41414141\n",
            regs: "rax=0000000041414141\nrip=0000000000401020\n",
            stack: "00000000`0012ff00 00000000`00401000 lab!ReadWild+0x8",
            disasm: "00401020  mov eax, dword ptr [rax]"),

        _ => throw new InvalidOperationException($"No ParseBlocks builder for stub/unknown fixture {env.FixtureId}"),
    };
}
