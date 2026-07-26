using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class DebuggerCorpusTests
{
    [Fact]
    public void All_cases_have_valid_expected_sidecars()
    {
        foreach (var caseId in DebuggerCorpusSupport.AllCaseIds())
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
    [InlineData("av-read", DebuggerAccessKind.Read, DebuggerAddressClass.Other)]
    [InlineData("ascii-write", DebuggerAccessKind.Write, DebuggerAddressClass.AsciiPattern)]
    public void Fixture_blocks_match_expected_without_cdb(
        string caseId,
        DebuggerAccessKind access,
        DebuggerAddressClass addressClass)
    {
        var expected = DebuggerCorpusSupport.LoadExpected(caseId);
        DebuggerObservation obs = caseId switch
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
            _ => throw new ArgumentOutOfRangeException(nameof(caseId)),
        };

        DebuggerCorpusSupport.AssertMatchesLoosely(expected, obs);
        Assert.Equal(access, obs.Access);
        Assert.Equal(addressClass, obs.FaultAddressClass);
    }

    [Theory]
    [InlineData("null-deref")]
    [InlineData("av-read")]
    public async Task Live_cdb_cases_match_expected(string caseId)
    {
        if (!DebuggerCorpusSupport.CanRunLiveCdbIntegration(out _))
            return;

        if (!File.Exists(DebuggerCorpusSupport.HarnessExePath()))
            return;

        var expected = DebuggerCorpusSupport.LoadExpected(caseId);
        if (expected.Stub)
            return;

        var obs = await DebuggerCorpusSupport.RunCaseLiveAsync(caseId);
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
        foreach (var caseId in new[] { "heap-overflow", "uaf" })
        {
            var expected = DebuggerCorpusSupport.LoadExpected(caseId);
            Assert.True(expected.Stub);
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
}
