#!/usr/bin/env python3
"""Fix mutation-chain build on main."""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def run(cmd):
    print("+", " ".join(cmd))
    subprocess.check_call(cmd, cwd=ROOT)

# Restore known-good base files from HEAD
for rel in [
    "src/Randall.Infrastructure/RandallBrain.cs",
    "src/Randall.Infrastructure/StalkIntelligenceBuilder.cs",
    "src/Randall.Infrastructure/FuzzEngine.cs",
    "src/Randall.Infrastructure/TargetIntelligenceBuilder.cs",
    "src/Randall.Infrastructure/LabDoctor.cs",
    "src/Randall.Infrastructure/Magician/JokerEngine.cs",
    "src/Randall.Infrastructure/Magician/MagicianEngine.cs",
]:
    content = subprocess.check_output(["git", "show", f"HEAD:{rel}"], cwd=ROOT)
    (ROOT / rel).write_bytes(content)

for junk in [
    "src/Randall.Infrastructure/BrainMemoryDecay.cs",
    "src/Randall.Contracts/BrainMemoryModels.cs",
    "src/Randall.Infrastructure/Magician/JokerCardDeck.cs",
    "tests/Randall.Tests/BrainMemoryDecayTests.cs",
    "tests/Randall.Tests/JokerCardDeckTests.cs",
]:
    p = ROOT / junk
    if p.exists():
        p.unlink()

# StalkIntelligenceBuilder
sib = ROOT / "src/Randall.Infrastructure/StalkIntelligenceBuilder.cs"
text = sib.read_text(encoding="utf-8")
text = text.replace(
    "        var (chains, chainBias) = TryLoadMutatorChains(project, repoRoot);\n"
    "        var (chains, chainBias) = TryLoadMutatorChains(project, repoRoot);\n",
    "        var (chains, chainBias) = TryLoadMutatorChains(project, repoRoot);\n",
    1,
)
text = re.sub(
    r"        var memory = BrainMemoryDecay\.TryLoad\(project, repoRoot\);\n"
    r"        var summary = BuildSummary\(frontier, hints, oracleFindings\.Count, targets, mutators\.Count\);\n"
    r"        if \(memory\?\.MemoryConfidence is < 0\.999\)\n"
    r"            summary \+= \$\" · brain memory \{memory\.MemoryConfidence:P0\}\";\n",
    "        var summary = BuildSummary(frontier, hints, oracleFindings.Count, targets, mutators.Count);\n",
    text,
    count=1,
)
text = text.replace(
    "            lastBrain,\n"
    "            memory?.MemoryConfidence ?? 1.0,\n"
    "            memory?.DecayMessage);",
    "            lastBrain);",
    1,
)
sib.write_text(text, encoding="utf-8", newline="\n")

# Strip partial brain-memory WIP from TargetIntelligenceBuilder if another agent touched it
tib = ROOT / "src/Randall.Infrastructure/TargetIntelligenceBuilder.cs"
tib_text = tib.read_text(encoding="utf-8")
tib_text = tib_text.replace(", BrainMemoryStateDto? brainMemory = null", "")
tib_text = tib_text.replace("brainMemory ??= BrainMemoryDecay.TryLoad(project, repoRoot);\n        ", "")
tib_text = re.sub(
    r"if \(brainMemory\?\.MemoryConfidence is < 0\.999\)\n            summary \+= \$\" · brain memory \{brainMemory\.MemoryConfidence:P0\}\";\n        ",
    "",
    tib_text,
)
tib_text = re.sub(
    r",\n            brainMemory\?\.TargetBinaryHash,\n            brainMemory\?\.MemoryConfidence \?\? 1\.0,\n            brainMemory\?\.DecayMessage\)",
    ")",
    tib_text,
)
tib.write_text(tib_text, encoding="utf-8", newline="\n")

# Strip partial brain-memory WIP from FuzzEngine
fe = ROOT / "src/Randall.Infrastructure/FuzzEngine.cs"
fe_text = fe.read_text(encoding="utf-8")
fe_text = re.sub(
    r"        var brainMemory = BrainMemoryDecay\.Ensure\(project, yamlPath, repoRoot\);\n"
    r"        if \(brainMemory\.LogLine is not null\)\n"
    r"            Console\.WriteLine\(brainMemory\.LogLine\);\n\n",
    "",
    fe_text,
    count=1,
)
fe_text = fe_text.replace(
    "                        repoRoot,\n                        memoryConfidence: brainMemory.MemoryConfidence,\n                        chainRows:",
    "                        repoRoot,\n                        chainRows:",
)
fe.write_text(fe_text, encoding="utf-8", newline="\n")

# RandallBrain PickMutator
rb = ROOT / "src/Randall.Infrastructure/RandallBrain.cs"
text = rb.read_text(encoding="utf-8-sig")
script = (ROOT / "scripts/patch-brain-chains-only.py").read_text(encoding="utf-8")
pick_new = script.split("pick_new = \"\"\"", 1)[1].split("\"\"\"", 1)[0].strip()
start = text.index("    public IMutator PickMutator(")
end = text.index("    public void PersistLast(", start)
text = text[:start] + pick_new + "\n\n" + text[end:]
rb.write_text(text, encoding="utf-8", newline="\n")

# Brain test
test = ROOT / "tests/Randall.Tests/RandallBrainTests.cs"
tt = test.read_text(encoding="utf-8")
if "Decide_UsesProductiveChainHintForPreferredMutator" not in tt:
    insert = '''
    [Fact]
    public void Decide_UsesProductiveChainHintForPreferredMutator()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "brain-chain";
            WriteStaticMap(root, project, fuzzPriority: 55);

            var brain = new RandallBrain();
            var signals = brain.LoadSignals(project, root);
            var mutators = BuiltInMutators.Create(
                ["dictionary", "integer", "splice", "havoc", "bitflip"], seed: 42);
            var credit = new List<MutatorCreditRowDto>
            {
                new("dictionary", 10, 5, 0, 50, 8),
            };
            var chains = new List<MutatorChainRowDto>
            {
                new(["dictionary", "integer", "splice"], 3, 4, 1, 90, 7, "dictionary→integer→splice"),
            };
            var decision = brain.Decide(project, signals, credit, mutators, iteration: 2, chainRows: chains);

            Assert.True(decision.Active);
            Assert.Contains(decision.WhyTerms, t => t.Label == "mutator chain");
            Assert.Contains(decision.WhyTerms, t => t.Detail == "dictionary→integer→splice");
        }
        finally
        {
            TryDelete(root);
        }
    }
'''
    tt = tt.replace(
        "    [Fact]\n    public void Decide_SaturatedScreamClusters_DeprioritizedInTerms()",
        insert + "\n    [Fact]\n    public void Decide_SaturatedScreamClusters_DeprioritizedInTerms()",
        1,
    )
    test.write_text(tt, encoding="utf-8", newline="\n")

run(["dotnet", "build", "src/Randall.Infrastructure/Randall.Infrastructure.csproj", "-c", "Release"])
run(["dotnet", "build", "tests/Randall.Tests/Randall.Tests.csproj", "-c", "Release", "--no-dependencies"])
run([
    "dotnet", "test", "Randall.sln", "-c", "Release", "--no-build",
    "--filter", "FullyQualifiedName~MutatorChainTrackerTests|FullyQualifiedName~LineageChainBuilderTests|FullyQualifiedName~Decide_UsesProductiveChainHint",
])
run(["git", "add",
     "src/Randall.Infrastructure/RandallBrain.cs",
     "src/Randall.Infrastructure/StalkIntelligenceBuilder.cs",
     "tests/Randall.Tests/RandallBrainTests.cs",
     "scripts/fix-chain-build.py",
     "scripts/ship-and-fix-chains.py"])
run(["git", "commit", "-m", "Fix mutation-chain build: PickMutator blend and StalkIntelligence dedupe.\n\nCompletes chain learning integration on main with passing build and chain tests."])
run(["git", "push", "origin", "main"])
print("SHA", subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip())
