using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class DynapstalkerExportTests
{
    [Fact]
    public void ParseModulesAndFilterEdges_ByProcessName()
    {
        var log = WriteSampleDrcov();
        try
        {
            var modules = DrcovParser.ParseModules(log);
            Assert.Contains(modules, m => m.Path.Contains("savant.exe", StringComparison.OrdinalIgnoreCase));

            var all = DrcovParser.ParseEdges(log);
            Assert.Equal(3, all.Count);

            var filtered = DrcovParser.ParseEdges(log, "savant.exe");
            Assert.Equal(2, filtered.Count);
            Assert.All(filtered, e => Assert.StartsWith("0:", e));
        }
        finally
        {
            TryDelete(Path.GetDirectoryName(log)!);
        }
    }

    [Fact]
    public void ExportIdc_WritesWhiteOnlyPaintAndFiltersProcess()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-dyna-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var log = WriteSampleDrcov(dir);
        var outIdc = Path.Combine(dir, "savant-base.idc");
        try
        {
            var result = DynapstalkerExport.ExportIdc(log, "savant.exe", outIdc, "0x00ffff");
            Assert.Equal(2, result.BlockCount);
            Assert.True(File.Exists(outIdc));
            var text = File.ReadAllText(outIdc);
            Assert.Contains("0x00FFFF", text, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("0xFFFFFFFF", text); // white-only guard
            Assert.Contains("0x00001000", text);
            Assert.DoesNotContain("0x0000BEEF", text); // other module filtered out
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void ExportGhidra_UsesImageBaseAndSkipsColored()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-ghidra-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var log = WriteSampleDrcov(dir);
        var outPy = Path.Combine(dir, "savant-base.py");
        try
        {
            var result = DynapstalkerExport.ExportGhidra(log, "savant.exe", outPy, "0x00ffff");
            Assert.Equal("ghidra", result.Format);
            Assert.Equal(2, result.BlockCount);
            var text = File.ReadAllText(outPy);
            Assert.Contains("getImageBase()", text);
            Assert.Contains("getBackgroundColor", text);
            Assert.Contains("base.add(rva)", text);
            Assert.Contains("4096", text); // 0x1000
            Assert.DoesNotContain("48879", text); // 0xbeef from ntdll filtered
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void Export_AutoDetectsGhidraFromPyExtension()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-auto-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var log = WriteSampleDrcov(dir);
        var outPy = Path.Combine(dir, "auto.py");
        try
        {
            var result = DynapstalkerExport.Export(log, "savant.exe", outPy, format: "", colorHex: "0x00ff00");
            Assert.Equal("ghidra", result.Format);
            Assert.Contains("ColorizingService", File.ReadAllText(outPy));
        }
        finally
        {
            TryDelete(dir);
        }
    }

    private static string WriteSampleDrcov(string? dir = null)
    {
        dir ??= Path.Combine(Path.GetTempPath(), "randall-drcov-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "drcov.savant.exe.00000.0000.proc.log");
        File.WriteAllText(path, """
            DRCOV VERSION: 2
            Module Table: version 2, count 2
            Columns: id, containing_id, start, end, entry, checksum, timestamp, path
             0, 0, 0x00400000, 0x00450000, 0x00401000, 0, 0, C:\DEV\savant.exe
             1, 1, 0x77000000, 0x77100000, 0x77001000, 0, 0, C:\Windows\System32\ntdll.dll
            BB Table: 3 bbs
            module id, start, size:
              0, 0x00001000, 16
              0, 0x00001100, 24
              1, 0x0000beef, 8
            """);
        return path;
    }

    private static void TryDelete(string dir)
    {
        try { Directory.Delete(dir, recursive: true); }
        catch { /* best effort */ }
    }
}
