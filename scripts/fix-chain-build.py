#!/usr/bin/env python3
"""Fix build for mutation-chain commit c90ed13."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# StalkIntelligenceBuilder: dedupe chains, drop broken BrainMemoryDecay refs
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
print("fixed StalkIntelligenceBuilder")

# RandallBrain: chain-aware PickMutator
rb = ROOT / "src/Randall.Infrastructure/RandallBrain.cs"
text = rb.read_text(encoding="utf-8-sig")
m = re.search(
    r"    public IMutator PickMutator\(\n.*?        return credit\.Pick\(mutators, rng\);\n    \}",
    text,
    re.DOTALL,
)
if not m:
    raise SystemExit("PickMutator block not found")
pick_new = (ROOT / "scripts/patch-brain-chains-only.py").read_text(encoding="utf-8")
pick_new = pick_new.split("pick_new = \"\"\"", 1)[1].split("\"\"\"", 1)[0].strip()
text = text.replace(m.group(0), pick_new, 1)
rb.write_text(text, encoding="utf-8", newline="\n")
print("fixed RandallBrain PickMutator")
