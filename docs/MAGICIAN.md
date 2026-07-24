# Magician engine (campaign actions)

The **Oracle** monitors each run and can request help when a finding needs more than a judgment.  
The **Magician** answers with **campaign actions**: dictionary, mutators, energy, coverage, Bug Hunter, or Joker enablement.

```text
Bug Hunter          Oracle                 Magician
───────────         ──────                 ────────
What to look for    Did it behave wrong?   What do we do next?
AI / robot code     findings + needs  →    campaign actions
randall hunt …      randall oracles …      randall magician …
```

| Engine | Role |
|--------|------|
| **Bug Hunter** | Attribute AI/human code, mistake catalog, arm oracles/dict |
| **Oracle** | Judge observations; emit findings; request help (`OracleNeedDto`) |
| **Magician** | Apply actions; enable hunter / coverage / mutators / bots / **joker** for analysts |

Code: `Randall.Infrastructure.Magician` (`MagicianEngine`, `JokerEngine`).

YAML action ids still use names like `summonKnight` for compatibility; logs describe the effect, not theater.

## Actions

| Action | Effect |
|--------|--------|
| `dictionaryBoost` | Inject framing / auth / AI-mistake tokens into the live dictionary |
| `havocSurge` | Ensure the havoc mutator is in the campaign |
| `energyBless` | Extra corpus energy on the offending input |
| `rearmOracles` | Merge the Bug Hunter oracle rule pack |
| `summonHunter` | Re-arm Bug Hunter (AI/robot mistake focus) |
| `summonKnight` | Enable `coverageGuided` stalking |
| `summonArmy` | Ensure a broad mutator set |
| `summonBots` | Write `bots_hint.md` for analysts (`randall ai seed` / `hunt`) — no live API on the hot path |
| `summonJoker` | Enable the **Joker** — encore of high-entropy iterations |
| `capitalizeJoker` | (automatic) After a Joker crash — corpus + energy + mutators |

## Joker

The **Joker** is not Magician. It runs **high-entropy** fuzz iterations (stacked mutators, wild bytes, optional session-bias overrides). Strategy labels in logs look like `stack-havoc+x3+wild`, not comedy names. Magician can:

1. **Enable** the Joker (`summonJoker` / `magician cast --need joker`)
2. **Sample** iterations (`joker_watch.jsonl`)
3. **Follow up** when a strategy crashes — retain corpus, boost energy, broaden mutators

```yaml
joker:
  enabled: true
  chance: 0.12          # base hijack rate
  maxStack: 4           # stacked mutators per iteration
  wildBytes: true
  flipSessionBias: true

magician:
  allowSummonJoker: true
  watchJoker: true
  capitalizeJokerCrashes: true
```

```bash
randall magician joker
randall magician cast -c projects/ai-badcode-hunt.yaml --need joker
```

## Oracle needs → Magician

| Need | Typical actions |
|------|-----------------|
| `dictionary` | dictionaryBoost, havocSurge |
| `energy` | energyBless |
| `hunter` | summonHunter, rearmOracles |
| `knight` | summonKnight |
| `army` | summonArmy, havocSurge |
| `bots` | summonBots |
| `joker` | summonJoker |
| `rearm` | rearmOracles |

Auth/state findings often request **hunter** + **bots** (AI-shaped logic). Integer/structure findings request the **army**. Differential/metamorphic findings request **coverage** (`knight`).

## Enable

```yaml
oracles:
  enabled: true

bugHunter:
  enabled: true
  autoArmOracles: true

magician:
  enabled: true
  autoCastOnOracle: true   # react to Oracle needs during fuzz
  blessOnStart: true       # opening mutator set + hunter arming
  persistSpells: true
  allowSummonHunter: true
  allowSummonKnight: true
  allowSummonArmy: true
  allowSummonBots: true
  # allowedSpells: [dictionaryBoost, summonArmy]   # optional allow-list
```

## CLI

```bash
randall magician spells
randall magician cast -c projects/ai-badcode-hunt.yaml --need army
randall magician cast -c projects/ai-badcode-hunt.yaml --need knight
randall magician cast -c projects/ai-badcode-hunt.yaml --need bots
randall magician -p ai-badcode-hunt
```

Actions persist under `data/crashes/<project>/_magician/spells.jsonl` (and `bots_hint.md` when bots are requested).

## Loop

```text
fuzz iteration
   → Oracle evaluates (judgment)
   → OracleNeeds from findings (foresight)
   → Magician applies actions
   → next iterations use updated dict / mutators / coverage
```

## Related

- [ORACLES.md](ORACLES.md) — judgment / reporting
- [BUG_HUNTER.md](BUG_HUNTER.md) — AI/robot code analysis
- [AI_SEED.md](AI_SEED.md) — optional bot-side seed recipes
- [LORE.md](LORE.md) — Oracle + Magician naming history
