# AI-codegen / AI-gateway labs (RAG1)

Fictional **RAG1** AI-gateway TCP lab for practicing fuzz campaigns against **LLM-codegen mistake classes** (length-lie, auth-skip, tool-bridge / output-bridge, mem-classic). This is **not** an LLM, inference server, OpenAI/Anthropic API, agent framework, or tool executor — no model calls, no shell, no real tool use.

| Lab | Port | Profile | Binary |
|-----|------|---------|--------|
| **VulnAi** | **18765/tcp** | `projects/vulnai.yaml` | `targets/vulnai/randall-vulnai` |

Source: `targets/Randall.VulnAi/` (handlers annotated `BEGIN AI` / `END AI`).  
Bug Hunter sample tree: `examples/vulnai-sample/`.

Pairs with the Bug Hunter / Oracle / Magician engines — see [BUG_HUNTER.md](BUG_HUNTER.md), [ORACLES.md](ORACLES.md), [MAGICIAN.md](MAGICIAN.md). The older demo profile `projects/ai-badcode-hunt.yaml` still targets VulnRpc; prefer **VulnAi** for a dedicated AI lab.

## Build

```bash
scripts/build-lab-targets.sh vulnai
# or
powershell -File scripts/build-vulnai.ps1
```

## Quick path

```bash
# Optional: hunt / arm from annotated sample
dotnet run --project src/Randall.Cli -- hunt -d examples/vulnai-sample -c projects/vulnai.yaml --arm

dotnet run --project src/Randall.Cli -- doctor -c projects/vulnai.yaml
dotnet run --project src/Randall.Cli -- fuzz   -c projects/vulnai.yaml
```

UI: Fuzz → Lab library → category **AI** → Start **VulnAi**.

## Wire format (lab-only)

Banner: `RAG1 AI READY`. Frames:

```
type_u8 | rem_len_u16_BE | body[rem_len]
```

| Type | Kind | Body sketch | Mistake class | Crash when |
|------|------|-------------|---------------|------------|
| `0x01` | INFER | **prompt_len** + prompt | length-lie / mem-classic | `prompt_len > 64` or prompt `> 64` |
| `0x02` | TOOL | **name_len** + name + **args_len** + args | output-bridge / path-inject | traversal/shell-shaped name + oversized join; `args_len > 128` |
| `0x03` | ADMIN | **token_len** + role/token | auth-skip | elevates on `admin` string; `token_len > 32` |
| any | — | — | — | `rem_len > 1024` |

Models: `protocols/vulnai_infer.yaml`, `vulnai_tool.yaml`, `vulnai_admin.yaml`.  
Dictionary: `dictionaries/ai_codegen_mistakes.txt`.

## Honest limits

- Loopback by default; do not expose on a public interface.
- Packets are deliberately **not** accepted by real AI gateways or model APIs.
- Crashes teach fuzz + Bug Hunter workflow — not evidence about commercial LLM products.
- Randfuzz will not ship weaponized prompts, jailbreak packs, or exploit templates for this lab.
