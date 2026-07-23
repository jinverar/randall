using System.Text;
using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Infrastructure.Rop;
using Xunit;

namespace Randall.Tests;

public class StackLensTests
{
    [Fact]
    public void MatchInput_RequiresActualInputOrDetectedCyclic()
    {
        // Non-cyclic binary garbage must not match via synthetic cyclic Offset
        var junk = Enumerable.Range(0, 64).Select(i => (byte)(i * 17 + 3)).ToArray();
        Assert.Null(StackLens.MatchInput("0x4141414141414141", junk));
        Assert.Null(StackLens.MatchInput("0x4141414141414141", null));

        var pattern = Encoding.ASCII.GetBytes(PatternTools.Create(120));
        var slice = pattern.AsSpan(40, 8).ToArray();
        var le = (byte[])slice.Clone();
        Array.Reverse(le);
        var hex = "0x" + Convert.ToHexString(le);
        Assert.Equal(40, StackLens.MatchInput(hex, pattern));
    }

    [Fact]
    public void ClassifyWord_DoesNotApplyGuideOffsetBlindlyToSp0()
    {
        // Unrelated SP+0 value must stay unknown even if guide says offset 72
        var word = StackLens.ClassifyWord(0, "RSP+0", "0x7ffdabcdef00", 8, input: null, guideOffset: 72);
        Assert.Null(word.InputOffset);
        Assert.NotEqual("controlled", word.Role);
    }

    [Fact]
    public void ClassifyWord_MarksCyclicControlledSlot()
    {
        var pattern = Encoding.ASCII.GetBytes(PatternTools.Create(200));
        // Take 8 bytes at offset 64 as a little-endian "register" value
        var slice = pattern.AsSpan(64, 8).ToArray();
        var le = (byte[])slice.Clone();
        Array.Reverse(le);
        var hex = "0x" + Convert.ToHexString(le);

        var word = StackLens.ClassifyWord(8, "RSP+0x8", hex, 8, pattern);
        Assert.Equal("controlled", word.Role);
        Assert.Equal(64, word.InputOffset);
    }

    [Fact]
    public void ClassifyWord_MarksNearSpCodePointerAsReturnSlot()
    {
        var word = StackLens.ClassifyWord(0, "0x7ffd0000", "0x7FF712345678", 8, input: null);
        Assert.Equal("return-slot", word.Role);
    }

    [Fact]
    public void ClassifyWord_RejectsAsciiPatternAsCodePointer()
    {
        // Printable cyclic-looking qword should not be return-slot without input match
        var word = StackLens.ClassifyWord(0, "RSP+0", "0x6141316141306141", 8, input: null);
        Assert.NotEqual("return-slot", word.Role);
    }

    [Fact]
    public void AnalyzeCrash_MissingCrash_FailsHonestly()
    {
        var report = StackLens.AnalyzeCrash(Guid.NewGuid());
        Assert.Equal("crash not found", report.Error);
    }

    [Fact]
    public void AnalyzeCrash_RegistersOnly_WritesSidecar()
    {
        var root = Path.Combine(Path.GetTempPath(), $"randall_stack_lens_{Guid.NewGuid():N}");
        var project = "stack-lens-lab";
        var crashDir = Path.Combine(root, "data", "crashes", project);
        Directory.CreateDirectory(crashDir);
        try
        {
            var pattern = Encoding.ASCII.GetBytes(PatternTools.Create(120));
            var store = new CrashStore(crashDir);
            var saved = store.Save(project, 1, "cyclic", pattern, exitCode: -11);
            // analysis with RIP holding pattern @ 40
            var slice = pattern.AsSpan(40, 8).ToArray();
            var le = (byte[])slice.Clone();
            Array.Reverse(le);
            var ripHex = "0x" + Convert.ToHexString(le);
            var analysis = new CrashAnalysisDto(
                true, null, "0xC0000005", "AV", ripHex, null,
                new RegisterSnapshotDto(ripHex, "0x7ffd1000", "0x7ffd2000", null, null, null, null),
                [], null);
            CrashAnalysisWriter.Write(crashDir, saved.Id, analysis);

            var report = StackLens.AnalyzeCrash(saved.Id, repoRoot: root);
            Assert.Null(report.Error);
            Assert.Equal("registers-only", report.Source);
            Assert.NotNull(report.OutputPath);
            Assert.True(File.Exists(report.OutputPath!.Replace('/', Path.DirectorySeparatorChar)));
            Assert.NotNull(report.PrimaryControl);
            Assert.Equal(40, report.PrimaryControl!.InputOffset);
            Assert.Contains(report.Words, w => w.Role == "controlled" && w.InputOffset == 40);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Docs_MentionStackLens()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var text = File.ReadAllText(Path.Combine(root, "docs", "WINDBG_FUZZ_PKG.md"));
        Assert.Contains("stack lens", text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("_stack_lens.json", text, StringComparison.Ordinal);
    }
}
