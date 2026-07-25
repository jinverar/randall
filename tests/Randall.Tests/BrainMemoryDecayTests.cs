using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Infrastructure.Mutators;
using Xunit;

namespace Randall.Tests;

public class BrainMemoryDecayTests
{
    [Fact]
    public void Ensure_FirstRun_RecordsFingerprint()
    {
        var repo = CreateRepo(out var yamlPath, out var binaryPath, out _);
        File.WriteAllBytes(binaryPath, [1, 2, 3]);
        try
        {
            var cfg = ProjectLoader.Load(yamlPath);
            var result = BrainMemoryDecay.Ensure(cfg, yamlPath, repo);
            Assert.Equal(1.0, result.MemoryConfidence);
            Assert.NotNull(result.TargetBinaryHash);
        }
        finally { try { Directory.Delete(repo, true); } catch { } }
    }

    [Fact]
    public void Ensure_BinaryChange_AppliesDecayToCreditAndState()
    {
        var repo = CreateRepo(out var yamlPath, out var binaryPath, out _);
        File.WriteAllBytes(binaryPath, [1, 2, 3]);
        var cfg = ProjectLoader.Load(yamlPath);
        BrainMemoryDecay.Ensure(cfg, yamlPath, repo);
        var corpusDir = ProjectLoader.ResolvePath(yamlPath, cfg.Fuzz.CorpusDir);
        Directory.CreateDirectory(corpusDir);
        var creditPath = Path.Combine(corpusDir, "mutator_credit.txt");
        File.WriteAllText(creditPath, "havoc runs=10 newEdges=20 uniqueCrashes=2 score=400");
        File.WriteAllBytes(binaryPath, [9, 9, 9]);
        try
        {
            var result = BrainMemoryDecay.Ensure(cfg, yamlPath, repo);
            Assert.True(result.BinaryChanged);
            Assert.Equal(BrainMemoryDecay.DefaultRetentionRatio, result.MemoryConfidence);
            Assert.True(MutatorCreditTracker.TryParsePersistLine(File.ReadAllLines(creditPath)[0], out var entry));
            Assert.Equal(244, entry.Score);
        }
        finally { try { Directory.Delete(repo, true); } catch { } }
    }

    [Fact]
    public void Decide_ScalesScoresWhenMemoryConfidenceReduced()
    {
        var brain = new RandallBrain();
        var frontier = new FrontierReportDto("demo", DateTime.UtcNow.ToString("o"), "cfg", "test", 1, 1, null,
            [new FrontierBranchDto("a->b", "cfg-branch", 80, 2, 0.5, 1, 0.25, "parse", "0x1000", "0x2000", null, "door")], "hint");
        var signals = new RandallBrain.Signals(true, "frontier", frontier, null, null, [], []);
        var decision = brain.Decide("demo", signals, [], [new HavocMutator(new Random(1), 4)], 1,
            memoryConfidence: BrainMemoryDecay.DefaultRetentionRatio);
        Assert.Contains("memory=", decision.Summary, StringComparison.Ordinal);
        Assert.True(decision.FocusScore <= 49);
    }

    [Fact]
    public void Ensure_DecayDisabled_ResetsConfidenceOnBinaryChange()
    {
        var repo = CreateRepo(out var yamlPath, out var binaryPath, out _);
        File.WriteAllBytes(binaryPath, [1]);
        var cfg = ProjectLoader.Load(yamlPath);
        BrainMemoryDecay.Ensure(cfg, yamlPath, repo);
        File.WriteAllBytes(binaryPath, [2]);
        cfg.Fuzz.BrainMemoryDecay = false;
        try
        {
            var result = BrainMemoryDecay.Ensure(cfg, yamlPath, repo);
            Assert.Equal(1.0, result.MemoryConfidence);
        }
        finally { try { Directory.Delete(repo, true); } catch { } }
    }

    private static string CreateRepo(out string yamlPath, out string binaryPath, out string project)
    {
        project = "brain-mem-" + Guid.NewGuid().ToString("N")[..8];
        var repo = Path.Combine(Path.GetTempPath(), "randall-brain-mem-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(repo, "projects"));
        Directory.CreateDirectory(Path.Combine(repo, "targets", project));
        Directory.CreateDirectory(Path.Combine(repo, "data", "stalk", project));
        binaryPath = Path.Combine(repo, "targets", project, "target.bin");
        yamlPath = Path.Combine(repo, "projects", project + ".yaml");
        File.WriteAllText(yamlPath, $$"""
name: {{project}}
kind: file
target:
  executable: ../targets/{{project}}/target.bin
fuzz:
  corpusDir: ../data/corpus/{{project}}
  brainMemoryDecay: true
""");
        return repo;
    }
}
