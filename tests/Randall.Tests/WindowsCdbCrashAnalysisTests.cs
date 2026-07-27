using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class WindowsCdbCrashAnalysisTests
{
    [Fact]
    public void ParseAnalyzeOutput_extracts_exception_and_fault()
    {
        const string sample = """
            EXCEPTION_CODE: (c0000005) Access violation
            FAULTING_IP: 41414141
            FAULTING_MODULE: vulnserver.exe
            """;
        var parsed = WindowsCdbCrashAnalysisWriter.ParseAnalyzeOutput(sample);
        Assert.Equal("c0000005", parsed.ExceptionCode);
        Assert.Contains("ACCESS_VIOLATION", parsed.ExceptionHint!, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("0x41414141", parsed.FaultAddress);
        Assert.Equal("vulnserver", parsed.FaultModule);
    }

    [Fact]
    public void ParseExploitableOutput_extracts_classification()
    {
        const string sample = """
            Exploitability Classification: EXPLOITABLE
            Recommended Exploitation Strategy: stack buffer overflow
            """;
        var parsed = WindowsCdbCrashAnalysisWriter.ParseExploitableOutput(sample);
        Assert.Equal("EXPLOITABLE", parsed.Classification);
        Assert.Contains("stack buffer overflow", parsed.Description!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CrashTriage_uses_exploitable_for_severity()
    {
        var triage = CrashTriage.Classify(null, null, null, null, "EXPLOITABLE");
        Assert.Equal("critical", triage.Severity);
    }

    [Fact]
    public void LooksLikeWindowsDump_rejects_linux_core()
    {
        Assert.False(WindowsCdbCrashAnalysisWriter.LooksLikeWindowsDump("crash.core"));
    }

    [Fact]
    public void BuildScript_includes_expanded_cdb_probes()
    {
        var script = WindowsCdbCrashAnalysisWriter.BuildScript(null);
        Assert.Contains(".symfix", script, StringComparison.Ordinal);
        Assert.Contains(".reload", script, StringComparison.Ordinal);
        Assert.Contains("!analyze -v", script, StringComparison.Ordinal);
        Assert.Contains(".exr -1", script, StringComparison.Ordinal);
        Assert.Contains(".ecxr", script, StringComparison.Ordinal);
        Assert.Contains(" r", script, StringComparison.Ordinal);
        Assert.Contains("kv", script, StringComparison.Ordinal);
        Assert.Contains(" lm", script, StringComparison.Ordinal);
        Assert.Contains("u @rip-20 @rip+40", script, StringComparison.Ordinal);
        Assert.Contains("dq @rsp L40", script, StringComparison.Ordinal);
        Assert.Contains("!heap", script, StringComparison.Ordinal);
        Assert.Contains("!address", script, StringComparison.Ordinal);
        Assert.Contains("RANDFUZZ_LM_BEGIN", script, StringComparison.Ordinal);
        Assert.Contains("RANDFUZZ_HEAP_BEGIN", script, StringComparison.Ordinal);
        Assert.Contains("RANDFUZZ_ADDRESS_BEGIN", script, StringComparison.Ordinal);
    }

    [Fact]
    public void ExtractBlock_parses_marked_sections()
    {
        const string text = """
            noise
            RANDFUZZ_HEAP_BEGIN
            heap summary line
            RANDFUZZ_HEAP_END
            """;
        var block = WindowsCdbCrashAnalysisWriter.ExtractBlock(text, "RANDFUZZ_HEAP_BEGIN", "RANDFUZZ_HEAP_END");
        Assert.Contains("heap summary", block, StringComparison.Ordinal);
    }
}
