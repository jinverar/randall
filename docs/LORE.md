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

We are *not* building a Scream Extractor. We are building the thing that finds why your parser would need one. The **Scare Floor** is where test-case recipes get staged before the fuzz shift — homage naming, not an official Disney/Pixar product.

### Scares, screams & canisters (the crash vocabulary)

In the film, Monstropolis runs on **screams collected in canisters** — the scream is the *valuable harvested resource*, not the scary moment. Randfuzz uses the same three-beat vocabulary so a crash is something you **collect**, not just something that happened:

| Term | Meaning in Randfuzz |
|------|---------------------|
| **Scare** | The act — send fuzzed input to provoke the target |
| **Scream** | The target crashes (the exception/signal) |
| **Scream canister** | The **bottled crash** you keep — input + minidump/core + triage bundle (a crash artifact pack) |

So "Scream" is Leg 5 (crash capture), and a saved crash bundle is a **scream canister** — harvest the screams, don't just hear them.

### Harvest visuals (Crashes tab)

The Crashes view shows a **scare-floor harvest rack**: industrial canisters that fill as unique crashes and severity buckets grow. Empty → low → mid → full art swaps with live liquid fill and a pressure readout (*Scare it. Bottle the scream.*).

Assets live under `docs/assets/canisters/` (docs) and `src/Randall.Server/wwwroot/img/canisters/` (UI). Original factory-horror art — not Disney/Pixar product likenesses.

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
