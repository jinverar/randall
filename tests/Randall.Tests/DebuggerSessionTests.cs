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
    public void TryWriteOpenScript_skips_analyze_when_headless_output_exists()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var project = $"dbg-open-script-{Guid.NewGuid():N}";
        var projectDir = Path.Combine(root, "data", "crashes", project);
        Directory.CreateDirectory(projectDir);

        try
        {
            var id = Guid.NewGuid();
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
            var id = Guid.NewGuid();
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
