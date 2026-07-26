using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class SanitizerLogParserTests
{
    [Fact]
    public void TryParseFirst_AsanErrorLine_ExtractsCheckType()
    {
        const string line =
            "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60300000eff0 at pc 0x7f0b2c401234 bp 0x7fffabc sp 0x7fffabd";

        Assert.True(SanitizerLogParser.TryParseFirst(line, out var parsed));
        Assert.NotNull(parsed);
        Assert.Equal("AddressSanitizer", parsed!.Sanitizer);
        Assert.Equal("heap-buffer-overflow", parsed.CheckType);
        Assert.Equal(FaultSignalKind.HeapCorruption, SanitizerLogParser.MapCheckKind(parsed.CheckType));
    }

    [Fact]
    public void TryParseFirst_UbsanRuntimeError_Works()
    {
        const string line = "file.c:42:5: runtime error: division by zero";

        Assert.True(SanitizerLogParser.TryParseFirst(line, out var parsed));
        Assert.NotNull(parsed);
        Assert.Equal("UndefinedBehaviorSanitizer", parsed!.Sanitizer);
        Assert.Contains("div", parsed.CheckType, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ExtractAll_DeduplicatesRepeatedSummary()
    {
        const string text = """
            ==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1
            SUMMARY: AddressSanitizer: heap-buffer-overflow
            """;

        var all = SanitizerLogParser.ExtractAll(text);
        Assert.Single(all);
    }
}

public class SanitizerCoverageBackendTests
{
    [Fact]
    public void TryIngestTraceDirectory_ParsesRawSancovPcs()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-sancov-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, "target.sancov");
        try
        {
            using (var fs = File.Create(file))
            {
                fs.Write(BitConverter.GetBytes(0xC0DEC0DEC0DEC0DEUL));
                fs.Write(BitConverter.GetBytes(0x401000UL));
                fs.Write(BitConverter.GetBytes(0x401050UL));
            }

            var coverage = new CoverageSet();
            var added = SanitizerCoverageBackend.TryIngestTraceDirectory(coverage, dir);

            Assert.Equal(2, added);
            Assert.Equal(2, coverage.TotalEdges);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }
}
