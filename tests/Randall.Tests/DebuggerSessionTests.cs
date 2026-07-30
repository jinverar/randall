using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Infrastructure.Mutators;
using Randall.Infrastructure.Rop;
using Xunit;

namespace Randall.Tests;

public class DebuggerSessionTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public void ShouldOpenDumpOnCrash_follows_checkbox_only(bool openOnCrash, bool expected) =>
        Assert.Equal(expected, DebuggerSession.ShouldOpenDumpOnCrash(openOnCrash));

    [Fact]
    public void BuildOpenArgs_puts_z_first_and_uses_script_command_for_gui()
    {
        var dump = @"C:\crashes\demo.dmp";
        var script = @"C:\crashes\open.txt";
        var args = DebuggerSession.BuildOpenArgs(
            "-y \"srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols\" -snul",
            dump,
            script,
            DebuggerTools.KindWinDbgPreview);

        Assert.StartsWith($"-z \"{dump}\"", args, StringComparison.Ordinal);
        Assert.Contains("-c \"$$><C:/crashes/open.txt\"", args, StringComparison.Ordinal);
        Assert.DoesNotContain("-cf ", args, StringComparison.Ordinal);
        Assert.Contains("-y \"", args, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildOpenArgs_uses_cf_only_for_cdb()
    {
        var args = DebuggerSession.BuildOpenArgs(
            "",
            @"D:\a.dmp",
            @"D:\a.txt",
            DebuggerTools.KindCdb);

        Assert.Equal("-z \"D:\\a.dmp\" -cf \"D:\\a.txt\"", args);
    }

    [Fact]
    public void BuildOpenArgs_without_script_is_z_and_symbols_only()
    {
        var args = DebuggerSession.BuildOpenArgs("-snul", @"E:\x.dmp", null);
        Assert.Equal("-z \"E:\\x.dmp\" -snul", args);
    }

    [Fact]
    public void OpenDump_refuses_missing_dump_with_expected_path()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"randall-missing-{Guid.NewGuid():N}.dmp");
        var result = DebuggerSession.OpenDump(missing, DebuggerTools.KindWinDbg);
        Assert.False(result.Ok);
        Assert.Contains("No usable dump", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(Path.GetFullPath(missing), result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryWriteOpenScript_skips_analyze_when_headless_output_exists()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var project = $"dbg-open-script-{Guid.NewGuid():N}";
        var projectDir = Path.Combine(root, "data", "crashes", project);
        Directory.CreateDirectory(projectDir);

        try
        {
            var hash = InputHash.StackHash(new byte[] { 0x41 });
            var inputPath = Path.Combine(projectDir, $"{project}_1_{hash}.bin");
            File.WriteAllBytes(inputPath, [0x41]);

            var store = new CrashStore(projectDir);
            var saved = store.SaveEx(
                project, 1, "havoc", [0x41], -1073741819,
                buildSidecar: crashId => new CrashSidecarDto(
                    crashId, "run", 1, project, "CMD", "havoc", ["havoc"], null, "seed", [],
                    hash, inputPath,
                    1, -1073741819, "AV", "detail", null, 0, 0, "native",
                    null, null, null, null,
                    new TransportSnapshotDto("stdio", "", 0, false),
                    new FuzzSnapshotDto(false, false, "projects/x.yaml"),
                    DateTimeOffset.UtcNow));

            File.WriteAllText(
                WindowsCdbCrashAnalysisWriter.AnalyzeTextPathFor(projectDir, saved.Crash.Id),
                """
                EXCEPTION_CODE: (c0000005) Access violation
                FAULTING_IP: 41414141
                ANALYSIS_VERSION: 10
                STACK_TEXT:
                  ntdll!RtlUserThreadStart
                """);

            var scriptPath = RandfuzzDbgWalk.TryWriteOpenScript(saved.Crash.Id, root);
            Assert.NotNull(scriptPath);
            var text = File.ReadAllText(scriptPath!);
            Assert.Contains("Headless cdb !analyze already saved", text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("!analyze -v", text, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { Directory.Delete(projectDir, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void TryWriteOpenScript_runs_analyze_when_no_headless_output()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var project = $"dbg-open-script-{Guid.NewGuid():N}";
        var projectDir = Path.Combine(root, "data", "crashes", project);
        Directory.CreateDirectory(projectDir);

        try
        {
            var hash = InputHash.StackHash(new byte[] { 0x42 });
            var inputPath = Path.Combine(projectDir, $"{project}_1_{hash}.bin");
            File.WriteAllBytes(inputPath, [0x42]);

            var store = new CrashStore(projectDir);
            var saved = store.SaveEx(
                project, 1, "havoc", [0x42], -1073741819,
                buildSidecar: crashId => new CrashSidecarDto(
                    crashId, "run", 1, project, "CMD", "havoc", ["havoc"], null, "seed", [],
                    hash, inputPath,
                    1, -1073741819, "AV", "detail", null, 0, 0, "native",
                    null, null, null, null,
                    new TransportSnapshotDto("stdio", "", 0, false),
                    new FuzzSnapshotDto(false, false, "projects/x.yaml"),
                    DateTimeOffset.UtcNow));

            var scriptPath = RandfuzzDbgWalk.TryWriteOpenScript(saved.Crash.Id, root);
            Assert.NotNull(scriptPath);
            var text = File.ReadAllText(scriptPath!);
            Assert.Contains("!analyze -v", text, StringComparison.Ordinal);
        }
        finally
        {
            try { Directory.Delete(projectDir, recursive: true); } catch { /* ignore */ }
        }
    }
}
