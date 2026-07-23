# Fuzzing AI-generated programs

Dedicated lab library entry: **[AI_LAB.md](AI_LAB.md)** (VulnAi / RAG1).

Randfuzz splits responsibilities:

1. **Bug Hunter engine** — AI/human code analysis, mistake catalog, hunt planning, campaign arming — [BUG_HUNTER.md](BUG_HUNTER.md)
2. **Oracle engine** — judgment and reporting only — [ORACLES.md](ORACLES.md)
3. **Magician** — spells when Oracle asks for help — [MAGICIAN.md](MAGICIAN.md)

```bash
# Dedicated AI-gateway lab
scripts/build-lab-targets.sh vulnai
randall hunt -d examples/vulnai-sample -c projects/vulnai.yaml --arm
randall fuzz -c projects/vulnai.yaml

# Older VulnRpc-backed demo profile
randall hunt -d examples/ai-code-sample
randall oracles -p ai-badcode-hunt
```
