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
| `playJokerCard` | Queue a legendary Joker Card draw from the deck |
| `rewindScream` | (Deep Scream marked) TTD playbook + record/replay scripts — no hot-path capture |

### Rewind Scream (TTD — Deep Scream marked only)

When `fuzz.rewindScream: true`, the Magician casts `rewindScream` **only on marked Deep Scream crashes** (not every crash). Writes `{guid}_deep_scream_ttd.md`, record/replay `.cmd` launchers, and a WinDbg backward-query script. Best-effort WinDbg Preview open when a dump exists. Randfuzz does **not** record TTD traces during fuzz — see [DEEP_SCREAM_TTD.md](DEEP_SCREAM_TTD.md).

```yaml
fuzz:
  rewindScream: true
magician:
  enabled: true
  allowRewindScream: true
```

## Joker

The **Joker** is not the Magician. It throws **very random** fuzz decisions (stacked mutators, wild bytes, funny session-bias flips). The Magician can:

1. **Summon** the Joker (`summonJoker` / `magician cast --need joker`)
2. **Play a card** (`playJokerCard`) — queue a legendary deck draw for the next trick
3. **Watch** every trick (`joker_watch.jsonl`)
4. **Capitalize** when a trick crashes — keep the scream, bless energy, muster the army

### Joker Card deck (70/20/10)

When `joker.deckEnabled: true`, productive tricks are scored into `data/crashes/<project>/_magician/joker_deck.json`. Each deck draw uses weighted roulette:

| Mode | Default weight | Behavior |
|------|----------------|----------|
| **chaos** | 70% | Fresh stacked mutators + wild bytes |
| **remix** | 20% | Shuffle a known productive recipe |
| **replay** | 10% | Replay a legendary card verbatim |

Cards promote to **legendary** when cumulative score and productive uses cross `legendaryScoreThreshold` / `legendaryMinProductiveUses`. The Magician's `playJokerCard` spell forces the next draw into **replay** mode and prefers legendary cards.

```yaml
joker:
  enabled: true
  chance: 0.12
  deckEnabled: true
  chaosWeight: 70
  remixWeight: 20
  replayWeight: 10
  legendaryScoreThreshold: 50
  legendaryMinProductiveUses: 2
  maxStack: 4
  wildBytes: true
  flipSessionBias: true

magician:
  allowSummonJoker: true
  allowPlayJokerCard: true
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
