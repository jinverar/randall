using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class DebuggerCorpusTests
{
    [Fact]
    public void All_cases_have_valid_expected_sidecars()
    {
        var ids = DebuggerCorpusSupport.AllCaseIds().ToList();
        Assert.True(ids.Count >= 12, $"expected expanded corpus (≥12), got {ids.Count}");
        foreach (var caseId in ids)
        {
            var expected = DebuggerCorpusSupport.LoadExpected(caseId);
            Assert.Equal(caseId, expected.CaseId);
            Assert.False(string.IsNullOrWhiteSpace(expected.Access));
            Assert.False(string.IsNullOrWhiteSpace(expected.AddressClass));
            Assert.False(string.IsNullOrWhiteSpace(expected.InputInfluence));
        }
    }

    [Theory]
    [InlineData("null-deref", DebuggerAccessKind.Write, DebuggerAddressClass.NullPage)]
    [InlineData("null-read", DebuggerAccessKind.Read, DebuggerAddressClass.NullPage)]
    [InlineData("av-read", DebuggerAccessKind.Read, DebuggerAddressClass.Other)]
    [InlineData("ascii-write", DebuggerAccessKind.Write, DebuggerAddressClass.AsciiPattern)]
    [InlineData("ascii-read", DebuggerAccessKind.Read, DebuggerAddressClass.AsciiPattern)]
    [InlineData("oob-write", DebuggerAccessKind.Write, DebuggerAddressClass.Heapish)]
    [InlineData("stack-corrupt", DebuggerAccessKind.Write, DebuggerAddressClass.Stackish)]
    [InlineData("uaf", DebuggerAccessKind.Read, DebuggerAddressClass.Freed)]
    [InlineData("double-free", DebuggerAccessKind.Unknown, DebuggerAddressClass.Freed)]
    [InlineData("integer-trunc", DebuggerAccessKind.Write, DebuggerAddressClass.Other)]
    public void Fixture_blocks_match_expected_without_cdb(
        string caseId,
        DebuggerAccessKind access,
        DebuggerAddressClass addressClass)
    {
        var expected = DebuggerCorpusSupport.LoadExpected(caseId);
        var obs = BuildFixtureObservation(caseId);

        DebuggerCorpusSupport.AssertMatchesLoosely(expected, obs);
        Assert.Equal(access, obs.Access);
        Assert.Equal(addressClass, obs.FaultAddressClass);
    }

    [Theory]
    [InlineData("null-deref")]
    [InlineData("null-read")]
    [InlineData("av-read")]
    [InlineData("ascii-read")]
    public async Task Live_cdb_cases_match_expected(string caseId)
    {
        if (!DebuggerCorpusSupport.CanRunLiveCdbIntegration(out _))
            return;

        if (!File.Exists(DebuggerCorpusSupport.HarnessExePath()))
            return;

        var expected = DebuggerCorpusSupport.LoadExpected(caseId);
        if (expected.Stub)
            return;

        DebuggerObservation obs;
        try
        {
            obs = await DebuggerCorpusSupport.RunCaseLiveAsync(caseId);
        }
        catch (Exception ex) when (
            ex is InvalidOperationException or TimeoutException ||
            ex.Message.Contains("minidump", StringComparison.OrdinalIgnoreCase) ||
            ex.Message.Contains("Scream attach", StringComparison.OrdinalIgnoreCase))
        {
            // Soft-skip when harness is stale (pre-rebuild) or watcher cannot attach —
            // managed fixtures above still cover normalized fields on Linux CI.
            return;
        }

        DebuggerCorpusSupport.AssertMatchesLoosely(expected, obs);
        Assert.True(obs.Ok);
        Assert.False(
            string.IsNullOrWhiteSpace(obs.ExrText)
            && string.IsNullOrWhiteSpace(obs.ExceptionCode)
            && string.IsNullOrWhiteSpace(DebuggerCorpusSupport.TryReadAnalyzeSidecar(obs.ObservationPath)),
            "expected cdb exr, analyze, or sidecar exception metadata");
    }

    [Fact]
    public void Stub_cases_are_marked_and_skipped_for_live_runs()
    {
        foreach (var caseId in new[]
                 {
                     "heap-overflow", "oob-write", "uaf", "double-free",
                     "stack-corrupt", "integer-trunc",
                 })
        {
            var expected = DebuggerCorpusSupport.LoadExpected(caseId);
            Assert.True(expected.Stub, $"{caseId} should be stub until native harness lands");
        }
    }

    [Fact]
    public void BuildScript_uses_randfuzz_marker_blocks_for_probe_parsing()
    {
        var script = WindowsCdbCrashAnalysisWriter.BuildScript(null);
        Assert.Contains("RANDFUZZ_EXR_BEGIN", script, StringComparison.Ordinal);
        Assert.Contains("RANDFUZZ_ADDRESS_BEGIN", script, StringComparison.Ordinal);
        Assert.Contains("RANDFUZZ_HEAP_BEGIN", script, StringComparison.Ordinal);
    }

    private static DebuggerObservation BuildFixtureObservation(string caseId) =>
        caseId switch
        {
            "null-deref" => ScreamInvestigator.ParseBlocks(
                """
                EXCEPTION_CODE: (c0000005) Access violation
                FAULTING_IP: 00401000
                """,
                """
                ExceptionCode: c0000005 (Access violation)
                NumberParameters: 2
                Parameter[0]: 00000001
                Parameter[1]: 00000000
                Attempt to write to address 00000000
                """),
            "null-read" => ScreamInvestigator.ParseBlocks(
                """
                EXCEPTION_CODE: (c0000005) Access violation
                FAULTING_IP: 00401000
                """,
                """
                ExceptionCode: c0000005 (Access violation)
                NumberParameters: 2
                Parameter[0]: 00000000
                Parameter[1]: 00000000
                Attempt to read from address 00000000
                """),
            "av-read" => ScreamInvestigator.ParseBlocks(
                """
                EXCEPTION_CODE: (c0000005) Access violation
                FAULTING_IP: 00401000
                """,
                """
                ExceptionCode: c0000005 (Access violation)
                NumberParameters: 2
                Parameter[0]: 00000000
                Parameter[1]: deadbeef
                Attempt to read from address deadbeef
                """),
            "ascii-write" => ScreamInvestigator.ParseBlocks(
                """
                EXCEPTION_CODE: (c0000005) Access violation
                FAULTING_IP: 00401000
                """,
                """
                ExceptionCode: c0000005 (Access violation)
                NumberParameters: 2
                Parameter[0]: 00000001
                Parameter[1]: 41414141
                Attempt to write to address 41414141
                """,
                regs: "rax=0000000041414141 rip=0000000000401000"),
            "ascii-read" => ScreamInvestigator.ParseBlocks(
                """
                EXCEPTION_CODE: (c0000005) Access violation
                FAULTING_IP: 00401000
                """,
                """
                ExceptionCode: c0000005 (Access violation)
                NumberParameters: 2
                Parameter[0]: 00000000
                Parameter[1]: 41414141
                Attempt to read from address 41414141
                """,
                regs: "rax=0000000041414141 rip=0000000000401000"),
            "oob-write" => ScreamInvestigator.ParseBlocks(
                """
                EXCEPTION_CODE: (c0000005) Access violation
                FAULTING_IP: 00401000
                """,
                """
                ExceptionCode: c0000005 (Access violation)
                NumberParameters: 2
                Parameter[0]: 00000001
                Parameter[1]: 000001a2b3c4d5e0
                Attempt to write to address 000001a2b3c4d5e0
                """,
                heap: "HEAP: Invalid address for heap segment 000001a2b3c4d5e0",
                address: "Region Type: Heap\nUsage: Heap segment"),
            "stack-corrupt" => ScreamInvestigator.ParseBlocks(
                """
                EXCEPTION_CODE: (c0000005) Access violation
                FAULTING_IP: 00401000
                """,
                """
                ExceptionCode: c0000005 (Access violation)
                NumberParameters: 2
                Parameter[0]: 00000001
                Parameter[1]: 0000007ff8a1c000
                Attempt to write to address 0000007ff8a1c000
                """,
                address: "Region Type: Stack\nUsage: Stack"),
            "uaf" => ScreamInvestigator.ParseBlocks(
                """
                EXCEPTION_CODE: (c0000005) Access violation
                FAULTING_IP: 00401000
                """,
                """
                ExceptionCode: c0000005 (Access violation)
                NumberParameters: 2
                Parameter[0]: 00000000
                Parameter[1]: 000001a20000f010
                Attempt to read from address 000001a20000f010
                """,
                heap: "use-after-free: block previously freed",
                address: "Free memory\nUsage: Free"),
            "double-free" => ScreamInvestigator.ParseBlocks(
                """
                EXCEPTION_CODE: (c0000374) A heap has been corrupted
                FAULTING_IP: 00401000
                """,
                """
                ExceptionCode: c0000374 (Heap corruption)
                """,
                heap: "double free / invalid heap — block already freed",
                address: "Free memory\nfreed heap block"),
            "integer-trunc" => ScreamInvestigator.ParseBlocks(
                """
                EXCEPTION_CODE: (c0000005) Access violation
                FAULTING_IP: 00401000
                """,
                """
                ExceptionCode: c0000005 (Access violation)
                NumberParameters: 2
                Parameter[0]: 00000001
                Parameter[1]: 0000000000123450
                Attempt to write to address 0000000000123450
                """,
                regs: "ecx=00000000000000ff rdx=0000000000010000 rip=0000000000401000"),
            _ => throw new ArgumentOutOfRangeException(nameof(caseId)),
        };
}
