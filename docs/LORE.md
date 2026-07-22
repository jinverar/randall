# Randfuzz by Randall — mascot & lore

**Randfuzz** is the product. **Randall** is the mascot — Randall Boggs (*Monsters, Inc.*) is the spirit animal: stealthy, competitive, always hunting the edge case nobody else saw.

> **Stalk code paths. Scream on crash.**

---

## Character → fuzzing parody

In the film, Randall is the master of camouflage, obsessed with beating Sulley, and willing to go off-script to win. For vulnerability research, that maps cleanly:

| Randall (film) | Randfuzz (product) |
|----------------|------------------|
| 🦎 **Camouflages** like a chameleon — nearly invisible | Blends into normal traffic: valid shells, plausible protocols, MITM proxy |
| 🐛 **Competitive scarer** — wants to beat Sulley | Coverage-guided corpus: prioritize inputs that **beat** the last best path |
| 🧪 **Sneaks** through the factory undetected | **Stalk** — DynamoRIO drcov, new basic blocks, unexplored code paths |
| 💥 **Collects screams** — the factory's whole purpose | **Scream** — you *scare* the target, it *screams* (crashes), and you **bottle that scream in a canister** (crash + minidump + triage bundle) |
| 🕵️ **Another trick up his sleeve** | Havoc stages, dictionary tokens, session flows, RPP plugins |
| 🏭 **Factory floor** — Monsters, Inc. pipeline | Eight legs: Model → Mutate → Send → Stalk → Scream → Proxy → Web → Pack |
| 🚪 **Scare Floor** — prep doors / scare attempts | **Scare Floor** UI — case recipes, seeds, dictionaries → Campaign queue |
| 🔮 **Oracle** — sees what others miss | **Oracle engine** — monitors runs, judges wrong-but-alive behavior, asks for help |
| 🪄 **Magician** — tricks up the sleeve | **Magician engine** — casts spells on the target; summons knight / army / bots / Bug Hunter |

We are *not* building a Scream Extractor. We are building the thing that finds why your parser would need one. The **Scare Floor** is where test-case recipes get staged before the fuzz shift — homage naming, not an official Disney/Pixar product.

### Oracle, Magician & the hunt crew

When the **Oracle** watches a campaign and sees a logic/auth/state miss (especially in AI/robot-authored code), it does more than log a finding — it can **request** a helper. The **Magician** answers:

| Summon | Magician power | Real effect |
|--------|----------------|-------------|
| **Hunter** | Call the Bug Hunter | Re-arm AI-mistake oracles / dictionary |
| **Knight** | Stalk the unexplored | Enable coverage-guided stalking |
| **Army** | Overwhelm the target | Muster a broad mutator set |
| **Bots** | Analyst helpers | Hint file for `randall ai seed` / `hunt` (off hot path) |
| **Joker** | Chaos agent | Very random stacked tricks; Magician watches and capitalizes on crashes |

### Joker (chaos, not craft)

The Magician plans; the **Joker** clown-cars into the scare floor with rubber-chicken mutations — stacked mutators, wild bytes, flipped session bias. Magician **watches** the act. When the Joker somehow crashes the target, Magician **capitalizes**: bottle the scream, bless corpus energy, muster the army on that punchline. See [MAGICIAN.md#joker](MAGICIAN.md#joker).

Spells (dictionary boost, havoc surge, energy bless, re-arm) act directly on the live fuzz campaign. Full map: [MAGICIAN.md](MAGICIAN.md).

### Scares, screams & canisters (the crash vocabulary)

In the film, Monstropolis runs on **screams collected in canisters** — the scream is the *valuable harvested resource*, not the scary moment. Randfuzz uses the same three-beat vocabulary so a crash is something you **collect**, not just something that happened:

| Term | Meaning in Randfuzz |
|------|---------------------|
| **Scare** | The act — send fuzzed input to provoke the target |
| **Scream** | The target crashes (the exception/signal) |
| **Scream canister** | The **bottled crash** you keep — input + minidump/core + triage bundle (a crash artifact pack) |

So "Scream" is Leg 5 (crash capture), and a saved crash bundle is a **scream canister** — harvest the screams, don't just hear them.

### Harvest visuals (Crashes tab)

The Crashes view shows a **scare-floor harvest rack**: one industrial canister per Target profile.
Atmosphere follows fixed thresholds (EIP seal still wins):

| Mood | Threshold | Feel |
|------|-----------|------|
| **laughter** | 0 unique screams | Great / warm — not sinister |
| **yelp** (watching) | 1–2 unique | Mild |
| **toxic** | 3–7 unique, or any critical | Toxic vapors + floating scares |
| **virulent** | ≥8 unique, or ≥3 critical | More toxic / sinister |
| **EIP seal** | classic EIP/RIP overwrite | Special seal (`canister-eip.jpg` + badge + EIP CAPTURED) |

Each canister shows mood art, a **porthole fill** (progressive toward capacity, mood-floored), and a small **pressure gauge**. Floating scare silhouettes (humans / doors / eyes) densify as the floor gets toxic; clean tests get laughter wisps instead. Continuous animations stay **off by default**.

Assets: `docs/assets/canisters/` · `/canisters/canister-*.jpg` (including `canister-eip.jpg`). Original factory-horror art — not Disney/Pixar product likenesses.

---

## Film traits (reference)

- **Master of stealth** — Randall camouflages himself to evade detection and sneak through the factory.
- **Competitive scarer** — Obsessed with beating Sulley for the top scarer spot.
- **Antagonist arc** — Works with Waternoose; the Scream Extractor plot is the villain beat in the movie.
- **Kidnaps Boo** — Part of the film's test-the-machine storyline.

**Lab use only:** Randfuzz is for systems you own or have explicit permission to test. The mascot is parody; the ethics are real.

---

## Taglines we use

| Line | Where |
|------|--------|
| *Stalk code paths. Scream on crash.* | README, roadmap, vulnserver banner |
| *Scare it. Bottle the scream.* | Crash capture / scream canisters |
| *Eight legs, zero mercy.* | RAND command response on lab vulnserver |
| *Chaos is my code.* | Web UI roadmap caption |
| *Master of mayhem.* | Web UI (Randfuzz by Randall at the console) |
| *Scare Floor* | Fuzz tab — case recipes / seed queue (not affiliated with Disney/Pixar) |

---

## Sulley & friends (tool genealogy)

| Name | Role in Randfuzz's world |
|------|-------------------------|
| **Sulley** | Sulley/Boofuzz — block-based generation fuzzing Randfuzz **complements** with coverage + stalking |
| **CANAPE** | Leg 6 — see the protocol before you fuzz it |
| **PaiMei / pStalker** | Leg 4 — coverage novelty, crash stalking, color-coded path maps (see README stalking diagram) |
| **Boo** | The innocent input that still finds the bug (your seed corpus) |

---

## Eight legs

Randall (the mascot) has eight legs — eight feature areas. See [LEGS.md](LEGS.md) for the learning path.

```
        ┌── Model
       ╱├── Mutate
      ╱ ├── Send
 Randall ├── Stalk (coverage)
      ╲ ├── Scream (crashes)
       ╲├── Proxy
        └── Web / Pack
```

---

*Monsters, Inc. and Randall Boggs are property of Disney/Pixar. This project is an independent parody for security education.*
