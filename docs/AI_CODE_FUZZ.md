# Fuzzing AI-generated programs

This document moved: see **[BUG_HUNTER.md](BUG_HUNTER.md)**.

Randfuzz splits responsibilities:

1. **Bug Hunter engine** — AI/human code analysis, mistake catalog, hunt planning, campaign arming  
2. **Oracle engine** — judgment and reporting only ([ORACLES.md](ORACLES.md))

```bash
randall hunt -d examples/ai-code-sample
randall oracles -p ai-badcode-hunt
```
