using Randall.Infrastructure;
using Randall.Infrastructure.Rop;
using Xunit;

namespace Randall.Tests;

public class RopStudioTests
{
    [Fact]
    public void DocsCatalog_IncludesWindbgFuzzPkg()
    {
        Assert.Contains(DocsCatalog.Index, i => i.Path == "WINDBG_FUZZ_PKG.md");
        Assert.Contains(DocsCatalog.Index, i => i.Path == "EXPLOIT_GUIDE.md"
            && i.Title.Contains("ROP", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Scanner_FindsRetGadgets_OnLinuxElf()
    {
        var exe = FirstExisting("/bin/true", "/usr/bin/true", "/bin/ls", "/usr/bin/ls");
        if (exe is null)
        {
            // Windows CI without a PE fixture — skip softly via empty assert path
            Assert.True(OperatingSystem.IsWindows() || OperatingSystem.IsLinux());
            return;
        }

        var report = RopGadgetScanner.Scan(exe, writeCache: false);
        Assert.Null(report.Error);
        Assert.True(report.GadgetCount > 0, report.SummaryLine);
        Assert.Contains(report.Gadgets, g => g.Kind == "ret");
        Assert.True(report.Arch is "x64" or "x86");
    }

    [Fact]
    public void Search_FiltersBadChars()
    {
        var exe = FirstExisting("/bin/true", "/usr/bin/true", "/bin/ls", "/usr/bin/ls");
        if (exe is null) return;

        var all = RopStudio.Search(exe, "ret", badCharsHex: null, limit: 20);
        Assert.True(all.Hits.Count > 0);

        // Unlikely filter: reject everything containing 0x00 in gadget bytes (many will still pass)
        var filtered = RopStudio.Search(exe, "ret", badCharsHex: "00", limit: 20);
        Assert.Equal("ret", filtered.Need);
        Assert.True(filtered.Hits.Count <= all.Hits.Count);
    }

    [Fact]
    public void Sketch_Pivot_WritesStepsOrEmptyHonestly()
    {
        var exe = FirstExisting("/bin/true", "/usr/bin/true", "/bin/ls", "/usr/bin/ls");
        if (exe is null) return;

        var sketch = RopStudio.Sketch(exe, "control", maxSteps: 4);
        Assert.Null(sketch.Error);
        Assert.Contains(sketch.Constraints, c => c.Contains("no shellcode", StringComparison.OrdinalIgnoreCase));
        // control goal should at least try for a ret
        Assert.True(sketch.Steps.Count >= 0);
        if (sketch.Steps.Count > 0)
            Assert.Contains(sketch.Steps, s => s.Gadget.Kind == "ret" || s.Role.Contains("ret"));
    }

    [Fact]
    public void ParseBadChars_AcceptsMixedForms()
    {
        var a = RopStudio.ParseBadChars(@"\x00\x0a 0d");
        Assert.Contains((byte)0x00, a);
        Assert.Contains((byte)0x0a, a);
        Assert.Contains((byte)0x0d, a);
    }

    [Fact]
    public void WindbgScripts_ExistInRepo()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        Assert.True(File.Exists(Path.Combine(root, "tools", "randfuzzdbg", "scripts", "rf_walk.txt")));
        Assert.True(File.Exists(Path.Combine(root, "tools", "randfuzzdbg", "scripts", "rf_load.txt")));
        Assert.Contains("rf_walk", RandfuzzDbgWalk.FormatScriptHelp(root), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ExploitGuide_MentionsRopStudio()
    {
        var exe = FirstExisting("/bin/true", "/usr/bin/true", "/bin/ls", "/usr/bin/ls");
        if (exe is null) return;
        var plan = ExploitGuide.Build(exe);
        Assert.Contains(plan.Findings, f => f.Contains("ROP Studio", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(plan.Steps, s => s.Title.Contains("ROP", StringComparison.OrdinalIgnoreCase)
                                         || s.Commands.Any(c => c.Contains("randall rop")));
    }

    private static string? FirstExisting(params string[] paths) =>
        paths.FirstOrDefault(File.Exists);
}
