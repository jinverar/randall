using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class CdbProbeEngineTests
{
    [Fact]
    public void StandardCrash_script_includes_all_markers_and_probes()
    {
        var script = CdbScriptBuilder.BuildInline(CdbProbePlan.StandardCrash);
        Assert.Contains(".symfix", script, StringComparison.Ordinal);
        Assert.Contains(".reload", script, StringComparison.Ordinal);
        Assert.Contains("!analyze -v", script, StringComparison.Ordinal);
        Assert.Contains(".exr -1", script, StringComparison.Ordinal);
        Assert.Contains(".ecxr", script, StringComparison.Ordinal);
        Assert.Contains(" kv", script, StringComparison.Ordinal);
        Assert.Contains(" lm", script, StringComparison.Ordinal);
        Assert.Contains("u @rip-20 @rip+40", script, StringComparison.Ordinal);
        Assert.Contains("dq @rsp L40", script, StringComparison.Ordinal);
        Assert.Contains("!heap", script, StringComparison.Ordinal);
        Assert.Contains("!address", script, StringComparison.Ordinal);
        Assert.Contains(CdbMarkers.Begin(CdbProbeSection.Analyze), script, StringComparison.Ordinal);
        Assert.Contains(CdbMarkers.End(CdbProbeSection.Heap), script, StringComparison.Ordinal);
    }

    [Fact]
    public void StandardCrash_with_msec_loads_exploitable_section()
    {
        var script = CdbScriptBuilder.BuildInline(
            CdbProbePlan.StandardCrash,
            new CdbScriptOptions { MsecDllPath = @"C:\tools\msec.dll" });
        Assert.Contains("!exploitable", script, StringComparison.Ordinal);
        Assert.Contains(CdbMarkers.Begin(CdbProbeSection.Exploitable), script, StringComparison.Ordinal);
        Assert.Contains(@"C:\tools\msec.dll", script, StringComparison.Ordinal);
    }

    [Fact]
    public void HeapCrash_script_uses_heap_markers_only()
    {
        var script = CdbScriptBuilder.BuildInline(CdbProbePlan.HeapCrash);
        Assert.Contains("!heap -s", script, StringComparison.Ordinal);
        Assert.Contains("!heap -p", script, StringComparison.Ordinal);
        Assert.Contains(CdbMarkers.Begin(CdbProbeSection.Heap), script, StringComparison.Ordinal);
        Assert.Contains(CdbMarkers.Begin(CdbProbeSection.PageHeap), script, StringComparison.Ordinal);
        Assert.DoesNotContain("!analyze", script, StringComparison.Ordinal);
    }

    [Fact]
    public void WaitAttach_uses_second_chance_exception_policy()
    {
        var script = CdbScriptBuilder.BuildFile(
            CdbProbePlan.WaitAttach,
            new CdbScriptOptions { DumpPath = @"C:\dumps\wait.dmp" });

        Assert.Contains("RANDFUZZ_EXCEPTION_POLICY second-chance-only", script, StringComparison.Ordinal);
        Assert.Contains("sxn av", script, StringComparison.Ordinal);
        Assert.Contains("sxn c0000005", script, StringComparison.Ordinal);
        Assert.Contains($"{Environment.NewLine}g{Environment.NewLine}", script, StringComparison.Ordinal);
        Assert.Contains(".dump /ma", script, StringComparison.Ordinal);
        Assert.Contains(@"C:\dumps\wait.dmp", script, StringComparison.Ordinal);
        Assert.Contains(CdbMarkers.Begin(CdbProbeSection.WaitAttach), script, StringComparison.Ordinal);
        Assert.Contains(CdbMarkers.Begin(CdbProbeSection.CrashCapture), script, StringComparison.Ordinal);
        // Old ambiguous pattern: bare g then dump without sxn filters
        Assert.DoesNotContain("g\n.dump", script, StringComparison.Ordinal);
    }

    [Fact]
    public void InteractiveOpen_skips_analyze_when_headless_saved()
    {
        var script = CdbScriptBuilder.BuildFile(
            CdbProbePlan.InteractiveOpen,
            new CdbScriptOptions
            {
                PreambleEchoes = [".echo test"],
                RunAnalyzeIfMissing = false,
                AnalyzeAlreadySavedPath = @"C:\crashes\abc_analyze.txt",
            });
        Assert.Contains("Headless cdb !analyze already saved", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("!analyze -v", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void MarkerParser_extracts_named_sections()
    {
        const string text = """
            noise
            RANDFUZZ_ANALYZE_BEGIN
            EXCEPTION_CODE: (c0000005) Access violation
            RANDFUZZ_ANALYZE_END
            RANDFUZZ_EXR_BEGIN
            Parameter[0]: 00000001
            RANDFUZZ_EXR_END
            RANDFUZZ_HEAP_BEGIN
            heap line
            RANDFUZZ_HEAP_END
            """;
        var transcript = CdbMarkerParser.Parse(text);
        Assert.Contains("EXCEPTION_CODE", transcript.Get(CdbProbeSection.Analyze), StringComparison.Ordinal);
        Assert.Contains("Parameter[0]", transcript.Get(CdbProbeSection.Exception), StringComparison.Ordinal);
        Assert.Contains("heap line", transcript.Get(CdbProbeSection.Heap), StringComparison.Ordinal);
    }

    [Fact]
    public void MarkerParser_legacy_fallback_without_markers()
    {
        const string text = "EXCEPTION_CODE: (c0000005) Access violation\nFAULTING_IP: 41414141\n";
        var transcript = CdbMarkerParser.Parse(text);
        Assert.Contains("EXCEPTION_CODE", transcript.Get(CdbProbeSection.Analyze), StringComparison.Ordinal);
    }

    [Fact]
    public void WindowsCdbCrashAnalysisWriter_BuildScript_delegates_to_builder()
    {
        var legacy = WindowsCdbCrashAnalysisWriter.BuildScript(null);
        var direct = CdbScriptBuilder.BuildInline(CdbProbePlan.StandardCrash);
        Assert.Equal(direct, legacy);
    }

    [Fact]
    public void ParseBlocks_populates_provenance()
    {
        const string analyze = """
            EXCEPTION_CODE: (c0000005) Access violation
            FAULTING_IP: 004020e2
            FAULTING_MODULE: vuln.exe
            """;
        const string exr = """
            Parameter[0]: 00000001
            Parameter[1]: 41414141
            Attempt to write to address 41414141
            """;
        const string regs = "rip=00000000004020e2 rsp=000000000012ff00\n";

        var obs = ScreamInvestigator.ParseBlocks(analyze, exr, regs);
        Assert.NotNull(obs.Provenance);
        Assert.Equal("!analyze -v", obs.Provenance!.ExceptionCode!.Source);
        Assert.Equal(DebuggerFactConfidence.Medium, obs.Provenance.ExceptionCode.Confidence);
        Assert.Equal(".exr -1", obs.Provenance.FaultAddress!.Source);
        Assert.Equal(DebuggerFactConfidence.High, obs.Provenance.FaultAddress.Confidence);
        Assert.Equal(DebuggerAccessKind.Write, obs.Provenance.Access!.Value);
        Assert.Equal(DebuggerFactKind.Inferred, obs.Provenance.FaultAddressClass!.Kind);
    }
}
