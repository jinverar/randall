using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Infrastructure.Magician;
using Randall.Infrastructure.Mutators;
using Randall.Infrastructure.Rop;
using Xunit;

namespace Randall.Tests;

public class CorruptionChainTests
{
    [Fact]
    public void BuildClusterKey_enriches_with_debugger_observation()
    {
        var baseKey = CrashTriage.BuildClusterKey("proj", "access_violation", "0x41414141", "vuln.exe");
        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\nFAULTING_IP: 41414141\n",
            exr: "Attempt to write to address 41414141\n",
            regs: "rip=0000000041414141\n",
            stack: """
                00000000`0012ff00 00000000`00401000 vuln!HandleHello+0x42
                """);

        var enriched = CrashTriage.BuildClusterKey("proj", "access_violation", "0x41414141", "vuln.exe", obs);

        Assert.Equal(baseKey, CrashTriage.BuildClusterKey("proj", "access_violation", "0x41414141", "vuln.exe", null));
        Assert.Contains(":write", enriched, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("handlehello", enriched, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Build_links_lineage_pattern_and_debugger()
    {
        var id = Guid.NewGuid();
        var payload = new byte[64];
        BitConverter.TryWriteBytes(payload.AsSpan(40), 0x41414141u);

        var sidecar = new CrashSidecarDto(
            id, "run", 7, "lab", "HELLO", "expand",
            ["bitflip", "expand"], null, "seed", [], "DEADBEEF", "x.bin", payload.Length,
            -1073741819, "ACCESS_VIOLATION", "server exited", null, 0, 0, "native",
            null, null, null, null,
            new TransportSnapshotDto("tcp", "127.0.0.1", 9999, false),
            new FuzzSnapshotDto(false, false, "projects/lab.yaml"),
            DateTimeOffset.UtcNow);

        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Attempt to write to address 41414141\nParameter[1]: 41414141\n",
            regs: "rip=0000000041414141\n",
            stack: "00000000`0012ff00 00000000`00401000 lab!Parse+0x10",
            sidecar: sidecar);

        var triage = CrashTriage.Classify(null, sidecar, null, payload, debugger: obs);
        var chain = CorruptionChainBuilder.Build(id, "lab", sidecar, obs, triage, payload);

        Assert.True(chain.Ok);
        Assert.Equal("HIGH", chain.Confidence);
        Assert.Equal("expand", chain.SuspectedMutator);
        Assert.Contains(chain.Steps, s => s.Kind == "mutation");
        Assert.Contains(chain.Steps, s => s.Kind == "input-offset");
        Assert.NotNull(chain.PatternDepthBytes);
    }

    [Fact]
    public void PersistForCrash_writes_json_sidecar()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randfuzz-chain-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            var chain = CorruptionChainBuilder.PersistForCrash(
                dir, id, "lab", null, null, null, null);

            var path = CorruptionChainBuilder.PathFor(dir, id);
            Assert.True(File.Exists(path));
            var loaded = CorruptionChainBuilder.TryRead(path);
            Assert.NotNull(loaded);
            Assert.Equal(chain.CrashId, loaded!.CrashId);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void TryWriteOpenScript_includes_corruption_chain_echo()
    {
        var root = CrashCatalog.FindRepoRoot();
        if (root is null)
            return;

        var project = "chain-open-" + Guid.NewGuid().ToString("N")[..8];
        var projectDir = Path.Combine(root, "data", "crashes", project);
        try
        {
            var store = new CrashStore(projectDir);
            var payload = new byte[] { 0x41, 0x41, 0x41, 0x41 };
            var hash = InputHash.StackHash(payload);
            var inputPath = Path.Combine(projectDir, $"{project}_1_{hash}.bin");
            var saved = store.SaveEx(
                project, 1, "havoc", payload, -1073741819,
                buildSidecar: id => new CrashSidecarDto(
                    id, "run", 1, project, "CMD", "havoc", ["havoc"], null, "seed", [],
                    hash, inputPath,
                    payload.Length, -1073741819, "AV", "detail", null, 0, 0, "native",
                    null, null, null, null,
                    new TransportSnapshotDto("stdio", "", 0, false),
                    new FuzzSnapshotDto(false, false, "projects/x.yaml"),
                    DateTimeOffset.UtcNow));

            var sidecar = CrashSidecarWriter.TryRead(saved.Crash.SidecarPath!);
            CorruptionChainBuilder.PersistForCrash(
                projectDir, saved.Crash.Id, project, sidecar, null, null, payload);

            var scriptPath = RandfuzzDbgWalk.TryWriteOpenScript(saved.Crash.Id, root);
            Assert.NotNull(scriptPath);
            Assert.True(File.Exists(scriptPath));
            var text = File.ReadAllText(scriptPath!);
            Assert.Contains("Corruption chain", text, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("RANDFUZZ OPEN", text, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { Directory.Delete(projectDir, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void RewindScreamOnCrash_writes_hint_when_deep_scream_marked()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-deep-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
            var yaml = Path.Combine(root, "projects", "file-text.yaml");
            if (!File.Exists(yaml)) return;

            var project = ProjectLoader.Load(yaml);
            project.Fuzz.RewindScream = true;
            project.Fuzz.CrashesDir = dir;
            project.Magician ??= new MagicianConfig();
            project.Magician.Enabled = true;
            project.Magician.AllowRewindScream = true;
            project.Magician.PersistSpells = false;

            var id = Guid.NewGuid();
            var deepScream = DeepScreamBuilder.PersistForCrash(
                dir, id, project.Name, screamScore: 72, seenCount: 1,
                reproducible: true, minimized: true, dumpPath: "fake.dmp");

            var cast = MagicianEngine.RewindScreamOnCrash(
                project, yaml, id, "fake.dmp", deepScream, progress: null);

            Assert.NotNull(cast);
            Assert.Contains(cast!.Spells, s => s.Spell == "deepScream");
            Assert.True(File.Exists(DeepScreamBuilder.TtdHintPathFor(dir, id)));
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }
}
