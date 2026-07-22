# Magician engine (spells & summons)

The **Oracle** monitors each run and can *see ahead* — when a finding needs more than a judgment, it asks for help.  
The **Magician** answers: cast **spells** on the program under fuzz, and **summon** specialists when the Oracle needs a knight, an army, bots, or the Bug Hunter.

```text
Bug Hunter          Oracle                 Magician
───────────         ──────                 ────────
What to look for    Did it behave wrong?   What do we do next?
AI / robot code     findings + needs  →    spells + summons
randall hunt …      randall oracles …      randall magician …
```

| Engine | Role |
|--------|------|
| **Bug Hunter** | Attribute AI/human code, mistake catalog, arm oracles/dict |
| **Oracle** | Judge observations; emit findings; request help (`OracleNeedDto`) |
| **Magician** | Cast spells; summon hunter / knight / army / bots / **joker** for analysts |

Code: `Randall.Infrastructure.Magician` (`MagicianEngine`, `JokerEngine`).

## Spells

| Spell | Effect |
|-------|--------|
| `dictionaryBoost` | Inject framing / auth / AI-mistake tokens into the live dictionary |
| `havocSurge` | Ensure the havoc mutator is in the campaign |
| `energyBless` | Extra corpus energy on the offending input |
| `rearmOracles` | Merge the Bug Hunter oracle rule pack |
| `summonHunter` | Re-arm Bug Hunter (AI/robot mistake focus) |
| `summonKnight` | Enable `coverageGuided` stalking |
| `summonArmy` | Muster a broad mutator set |
| `summonBots` | Write `bots_hint.md` for analysts (`randall ai seed` / `hunt`) — no live API on the hot path |
| `summonJoker` | Call the **Joker** — encore of chaotic random tricks |
| `capitalizeJoker` | (automatic) After a Joker crash — corpus + energy + army |

## Joker

The **Joker** is not the Magician. It throws **very random** fuzz decisions (stacked mutators, wild bytes, funny session-bias flips). The Magician can:

1. **Summon** the Joker (`summonJoker` / `magician cast --need joker`)
2. **Watch** every trick (`joker_watch.jsonl`)
3. **Capitalize** when a trick crashes — keep the scream, bless energy, muster the army

```yaml
joker:
  enabled: true
  chance: 0.12          # base hijack rate
  maxStack: 4           # stacked mutators per trick
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

| Need | Typical spells |
|------|----------------|
| `dictionary` | dictionaryBoost, havocSurge |
| `energy` | energyBless |
| `hunter` | summonHunter, rearmOracles |
| `knight` | summonKnight |
| `army` | summonArmy, havocSurge |
| `bots` | summonBots |
| `joker` | summonJoker |
| `rearm` | rearmOracles |

Auth/state findings often summon **hunter** + **bots** (AI-shaped logic). Integer/structure findings summon the **army**. Differential/metamorphic findings summon the **knight**.

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
  blessOnStart: true       # opening army + hunter blessing
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

Casts persist under `data/crashes/<project>/_magician/spells.jsonl` (and `bots_hint.md` when bots are summoned).

## Loop

```text
fuzz iteration
   → Oracle evaluates (judgment)
   → OracleNeeds from findings (foresight)
   → Magician casts / summons
   → next iterations use blessed dict / mutators / coverage
```

## Related

- [ORACLES.md](ORACLES.md) — judgment / reporting
- [BUG_HUNTER.md](BUG_HUNTER.md) — AI/robot code analysis
- [AI_SEED.md](AI_SEED.md) — optional bot-side seed recipes
- [LORE.md](LORE.md) — Oracle + Magician parody mapping
