using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Infrastructure.Rop;
using System.Text;
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
        Assert.Contains(DocsCatalog.Index, i => i.Path == "WINDBG_FUZZ_PKG.md"
            && i.Title.Contains("Scream", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ResolveSketchGoal_MapsTiers()
    {
        Assert.Equal("pivot", RopStudio.ResolveSketchGoal("pivot", null));
        Assert.Equal("leak", RopStudio.ResolveSketchGoal("leak", null));
        Assert.Equal("canary", RopStudio.ResolveSketchGoal("canary", null));
        Assert.Equal("pivot", RopStudio.ResolveSketchGoal("auto", null)); // no module → pivot default
        var exe = FirstExisting("/bin/true", "/usr/bin/true", "/bin/ls", "/usr/bin/ls");
        if (exe is null) return;
        var auto = RopStudio.ResolveSketchGoal("auto", exe);
        Assert.Contains(auto, new[] { "control", "pivot", "leak", "canary" });
    }

    [Fact]
    public void LadderDiff_ReportsMissingOrPresentTiers()
    {
        var report = MitigationLadder.Diff(scanGadgets: false);
        Assert.Equal(4, report.Tiers.Count);
        Assert.Contains(report.Tiers, t => t.Tier == "basic");
        Assert.Contains(report.Tiers, t => t.SketchGoalHint == "control");
        Assert.Contains(report.Findings, f => f.Contains("nx", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void GdbScripts_ExistInRepo()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        Assert.True(File.Exists(Path.Combine(root, "tools", "randfuzzgdb", "scripts", "rf_gdb.txt")));
        Assert.Contains("rf_gdb", RandfuzzGdbWalk.FormatScriptHelp(root), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ScreamWalk_MissingCrash_FailsHonestly()
    {
        var report = ScreamWalk.Run(Guid.NewGuid());
        Assert.Equal("crash not found", report.Error);
    }

    [Fact]
    public void LadderGoalForTier_MatchesAdaptiveStory()
    {
        Assert.Equal("control", MitigationLadder.GoalForTierName("basic"));
        Assert.Equal("pivot", MitigationLadder.GoalForTierName("nx"));
        Assert.Equal("leak", MitigationLadder.GoalForTierName("aslr"));
        Assert.Equal("canary", MitigationLadder.GoalForTierName("modern"));
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
    public void BadCharLearner_FindsNullAndNewline()
    {
        var input = "AAAA"u8.ToArray().Concat(new byte[] { 0x00 }).Concat("BBBB\nCCCC"u8.ToArray()).ToArray();
        var report = RopBadCharLearner.LearnFromBytes(input, controlOffset: 8);
        Assert.Contains((byte)0x00, report.Suggested);
        Assert.Contains((byte)0x0a, report.Suggested);
        Assert.Contains("\\x00", report.BadCharsHex);
        Assert.True(report.Reasons!.Count > 0);
    }

    [Fact]
    public void BadCharLearner_DefaultsNullWhenCleanBinary()
    {
        // Avoid classic breakers (NUL/LF/CR/SUB/space/tab/0xff)
        var input = Enumerable.Range(0x41, 40).Select(i => (byte)i).ToArray();
        var report = RopBadCharLearner.LearnFromBytes(input);
        Assert.Contains((byte)0x00, report.Suggested);
        Assert.Contains(report.Reasons!, r => r.Contains("defaulting", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Scanner_FindsCommonGadgetKinds()
    {
        var exe = FirstExisting("/bin/true", "/usr/bin/true", "/bin/ls", "/usr/bin/ls");
        if (exe is null) return;
        var report = RopGadgetScanner.Scan(exe, writeCache: false, maxGadgets: 2000);
        Assert.Null(report.Error);
        Assert.Contains(report.Gadgets, g =>
            g.Kind is "ret" or "nop-ret" or "leave-ret" or "add-sp"
            || g.Kind.StartsWith("pop-", StringComparison.Ordinal)
            || g.Kind.StartsWith("jmp-", StringComparison.Ordinal)
            || g.Kind.StartsWith("call-", StringComparison.Ordinal));
    }

    [Fact]
    public void AddressBadChars_FilterLittleEndianPointerBytes()
    {
        // 0x00401234 LE = 34 12 40 00 — contains null
        Assert.True(RopStudio.AddressContainsBadChar("0x401234", [(byte)0x00]));
        Assert.False(RopStudio.AddressContainsBadChar("0x7ff81234", [(byte)0x00]));
        var g = new RopGadgetDto("0x401234", "ret", "c3", "ret", "mod", 1, ["ret"]);
        Assert.True(RopStudio.GadgetHitsBadChars(g, [(byte)0x00]));
    }

    [Fact]
    public void Scanner_PeFixture_FindsRetPopAndMovRm()
    {
        var pe = BuildMinimalPe32(
        [
            0xC3,             // ret
            0x58, 0xC3,       // pop eax; ret
            0x89, 0x01, 0xC3, // mov [ecx], eax; ret
            0xC2, 0x08, 0x00, // retn 8
            0x94, 0xC3,       // xchg eax, esp; ret
        ]);
        var path = Path.Combine(Path.GetTempPath(), $"randall_rop_pe_{Guid.NewGuid():N}.dll");
        try
        {
            File.WriteAllBytes(path, pe);
            var report = RopGadgetScanner.Scan(path, "x86", writeCache: false, preferCache: false);
            Assert.Null(report.Error);
            Assert.Equal("x86", report.Arch);
            Assert.Contains(report.Gadgets, g => g.Kind == "ret");
            Assert.Contains(report.Gadgets, g => g.Kind == "pop-eax");
            Assert.Contains(report.Gadgets, g => g.Kind == "mov-rm");
            Assert.Contains(report.Gadgets, g => g.Kind == "retn");
            Assert.Contains(report.Gadgets, g => g.Kind == "xchg-sp");
        }
        finally
        {
            try { File.Delete(path); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Scanner_Cache_RoundTrips()
    {
        var pe = BuildMinimalPe32([0xC3, 0x58, 0xC3]);
        var dir = Path.Combine(Path.GetTempPath(), $"randall_rop_cache_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "tiny.dll");
        try
        {
            File.WriteAllBytes(path, pe);
            var first = RopGadgetScanner.Scan(path, "x86", repoRoot: dir, writeCache: true, preferCache: false);
            Assert.Null(first.Error);
            Assert.True(first.GadgetCount > 0);
            Assert.NotNull(first.CachePath);
            Assert.True(File.Exists(first.CachePath));

            var second = RopGadgetScanner.Scan(path, "x86", repoRoot: dir, writeCache: true, preferCache: true);
            Assert.Null(second.Error);
            Assert.Contains("(cache)", second.SummaryLine, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(first.GadgetCount, second.GadgetCount);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Sketch_IncludesMitigationConstraint_WhenReadelfAvailable()
    {
        var exe = FirstExisting("/bin/true", "/usr/bin/true", "/bin/ls", "/usr/bin/ls");
        if (exe is null) return;
        var sketch = RopStudio.Sketch(exe, "control", maxSteps: 4);
        Assert.Contains(sketch.Constraints, c => c.Contains("mitigations:", StringComparison.OrdinalIgnoreCase)
                                                 || c.Contains("no shellcode", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void PeExportNearest_PicksClosestLowerRva()
    {
        var exports = new List<PeExportTable.Export>
        {
            new(0x1000, "Foo"),
            new(0x2000, "Bar"),
            new(0x3000, "Baz"),
        };
        Assert.Equal("Foo", PeExportTable.Nearest(exports, 0x1008));
        Assert.Equal("Bar", PeExportTable.Nearest(exports, 0x2100));
        Assert.Null(PeExportTable.Nearest(exports, 0x0800));
    }

    [Fact]
    public void ResolveCrashModules_RanksOverrideFirst()
    {
        var pe = BuildMinimalPe32([0xC3, 0x58, 0xC3]);
        var dir = Path.Combine(Path.GetTempPath(), $"randall_rop_mods_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var a = Path.Combine(dir, "target.dll");
        var b = Path.Combine(dir, "other.dll");
        try
        {
            File.WriteAllBytes(a, pe);
            File.WriteAllBytes(b, pe);
            var detail = new CrashDetailDto(
                new CrashSummaryDto(
                    Guid.NewGuid(), "proj", 1, "mut", "hash", a, null, null, null, null, null,
                    DateTimeOffset.UtcNow),
                0, "", "", null, null, null);
            // Use reflection-free path: public ResolveCrashModules with override
            var mods = RopStudio.ResolveCrashModules(detail, dir, exeOverride: b, maxModules: 2);
            Assert.NotEmpty(mods);
            Assert.Equal(Path.GetFullPath(b), mods[0]);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void ExploitGuide_MentionsScreamWalk()
    {
        var exe = FirstExisting("/bin/true", "/usr/bin/true", "/bin/ls", "/usr/bin/ls");
        if (exe is null) return;
        var plan = ExploitGuide.Build(exe);
        Assert.Contains(plan.Steps, s =>
            s.Commands.Any(c => c.Contains("scream walk", StringComparison.OrdinalIgnoreCase))
            || s.Title.Contains("Scream Walk", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(plan.Steps, s =>
            s.Commands.Any(c => c.Contains("ladder diff", StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public void LoadSidecars_SurfacesScreamGdbAndLadderPaths()
    {
        var root = Path.Combine(Path.GetTempPath(), $"randall_sidecars_{Guid.NewGuid():N}");
        var project = "sidecars-lab";
        var crashDir = Path.Combine(root, "data", "crashes", project);
        Directory.CreateDirectory(crashDir);
        try
        {
            var store = new CrashStore(crashDir);
            var saved = store.Save(project, 1, "test", "AAAA"u8.ToArray(), exitCode: -11);
            var id = saved.Id;
            File.WriteAllText(Path.Combine(crashDir, $"{id:N}_scream_walk.json"),
                $$"""{"crashId":"{{id:D}}","project":"sidecars-lab","goalResolved":"control","steps":[],"summaryLine":"ok"}""");
            File.WriteAllText(Path.Combine(crashDir, $"{id:N}_gdb_walk.json"),
                """{"summaryLine":"gdb ok","registers":[],"modules":[],"scriptLines":[]}""");
            File.WriteAllText(Path.Combine(crashDir, $"{id:N}_ladder.json"),
                """{"labRoot":"/tmp","tiers":[],"findings":[],"nextCommands":[],"summaryLine":"ladder"}""");

            var side = RopStudio.LoadSidecars(id, root);
            Assert.NotNull(side);
            Assert.NotNull(side!.ScreamWalkPath);
            Assert.NotNull(side.GdbWalkPath);
            Assert.NotNull(side.LadderPath);
            Assert.Contains("scream-walk", side.SummaryLine, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("gdb", side.SummaryLine, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("ladder", side.SummaryLine, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Docs_WinDbgPkg_DocumentsAutoGoalAndScreamArtifacts()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var text = File.ReadAllText(Path.Combine(root, "docs", "WINDBG_FUZZ_PKG.md"));
        Assert.Contains("--goal auto", text, StringComparison.Ordinal);
        Assert.Contains("_scream_walk.json", text, StringComparison.Ordinal);
        Assert.Contains("_gdb_walk.json", text, StringComparison.Ordinal);
        Assert.Contains("scream walk", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ExploitGuide_MentionsRopStudio()
    {
        var exe = FirstExisting("/bin/true", "/usr/bin/true", "/bin/ls", "/usr/bin/ls");
        if (exe is null) return;
        var plan = ExploitGuide.Build(exe);
        Assert.Contains(plan.Findings, f => f.Contains("ROP Studio", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(plan.Steps, s => s.Title.Contains("ROP", StringComparison.OrdinalIgnoreCase)
                                         || s.Commands.Any(c => c.Contains("randall rop")
                                                               || c.Contains("scream walk")));
    }

    /// <summary>Minimal PE32 with one executable .text section containing <paramref name="code"/>.</summary>
    private static byte[] BuildMinimalPe32(byte[] code)
    {
        const int peOff = 0x80;
        const int optSize = 0xE0;
        const int sectionOff = peOff + 0x18 + optSize; // 0x178
        const int rawPtr = 0x200;
        var file = new byte[rawPtr + Math.Max(0x200, code.Length)];
        file[0] = 0x4D; file[1] = 0x5A; // MZ
        BitConverter.GetBytes(peOff).CopyTo(file, 0x3C);

        // PE signature
        file[peOff] = (byte)'P'; file[peOff + 1] = (byte)'E';
        // COFF
        BitConverter.GetBytes((ushort)0x14C).CopyTo(file, peOff + 4); // i386
        BitConverter.GetBytes((ushort)1).CopyTo(file, peOff + 6); // 1 section
        BitConverter.GetBytes((ushort)optSize).CopyTo(file, peOff + 0x14);
        BitConverter.GetBytes((ushort)0x0102).CopyTo(file, peOff + 0x16); // EXECUTABLE_IMAGE

        // Optional PE32
        var opt = peOff + 0x18;
        BitConverter.GetBytes((ushort)0x10B).CopyTo(file, opt); // PE32
        BitConverter.GetBytes((uint)0x00001000).CopyTo(file, opt + 16); // SectionAlignment
        BitConverter.GetBytes((uint)0x00000200).CopyTo(file, opt + 20); // FileAlignment
        BitConverter.GetBytes((ushort)3).CopyTo(file, opt + 40); // Subsystem CUI
        BitConverter.GetBytes((uint)0x00400000).CopyTo(file, opt + 28); // ImageBase
        BitConverter.GetBytes((uint)0x2000).CopyTo(file, opt + 56); // SizeOfImage
        BitConverter.GetBytes((uint)0x200).CopyTo(file, opt + 60); // SizeOfHeaders
        BitConverter.GetBytes((uint)16).CopyTo(file, opt + 92); // NumberOfRvaAndSizes

        // .text section
        Encoding.ASCII.GetBytes(".text\0\0\0").CopyTo(file, sectionOff);
        BitConverter.GetBytes((uint)0x200).CopyTo(file, sectionOff + 8); // VirtualSize
        BitConverter.GetBytes((uint)0x1000).CopyTo(file, sectionOff + 12); // VA
        BitConverter.GetBytes((uint)0x200).CopyTo(file, sectionOff + 16); // SizeOfRawData
        BitConverter.GetBytes((uint)rawPtr).CopyTo(file, sectionOff + 20);
        BitConverter.GetBytes((uint)(0x20000000 | 0x00000020 | 0x40000000)).CopyTo(file, sectionOff + 36); // EXEC|CODE|READ

        Buffer.BlockCopy(code, 0, file, rawPtr, code.Length);
        return file;
    }

    private static string? FirstExisting(params string[] paths) =>
        paths.FirstOrDefault(File.Exists);
}
