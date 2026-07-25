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
        Assert.Equal("vulnserver.exe", parsed.FaultModule);
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
}
