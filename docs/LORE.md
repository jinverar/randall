# Randall — mascot & lore

Randall Boggs (*Monsters, Inc.*) is the spirit animal of this fuzzer: stealthy, competitive, always hunting the edge case nobody else saw.

> **Stalk code paths. Scream on crash.**

---

## Character → fuzzing parody

In the film, Randall is the master of camouflage, obsessed with beating Sulley, and willing to go off-script to win. For vulnerability research, that maps cleanly:

| Randall (film) | Randall (fuzzer) |
|----------------|------------------|
| 🦎 **Camouflages** like a chameleon — nearly invisible | Blends into normal traffic: valid shells, plausible protocols, MITM proxy |
| 🐛 **Competitive scarer** — wants to beat Sulley | Coverage-guided corpus: prioritize inputs that **beat** the last best path |
| 🧪 **Sneaks** through the factory undetected | **Stalk** — DynamoRIO drcov, new basic blocks, unexplored code paths |
| 💥 **Triggers chaos** — Scream Extractor, kidnaps Boo | **Scream** — crash capture, minidumps, triage bundles, Ghidra export |
| 🕵️ **Another trick up his sleeve** | Havoc stages, dictionary tokens, session flows, RPP plugins |
| 🏭 **Factory floor** — Monsters, Inc. pipeline | Eight legs: Model → Mutate → Send → Stalk → Scream → Proxy → Web → Pack |

We are *not* building a Scream Extractor. We are building the thing that finds why your parser would need one.

---

## Film traits (reference)

- **Master of stealth** — Randall camouflages himself to evade detection and sneak through the factory.
- **Competitive scarer** — Obsessed with beating Sulley for the top scarer spot.
- **Antagonist arc** — Works with Waternoose; the Scream Extractor plot is the villain beat in the movie.
- **Kidnaps Boo** — Part of the film's test-the-machine storyline.

**Lab use only:** Randall the fuzzer is for systems you own or have explicit permission to test. The mascot is parody; the ethics are real.

---

## Taglines we use

| Line | Where |
|------|--------|
| *Stalk code paths. Scream on crash.* | README, roadmap, vulnserver banner |
| *Eight legs, zero mercy.* | RAND command response on lab vulnserver |
| *Chaos is my code.* | Web UI roadmap caption |
| *Master of mayhem.* | Web UI (Randall at the console) |

---

## Sulley & friends (tool genealogy)

| Name | Role in Randall's world |
|------|-------------------------|
| **Sulley** | Sulley/Boofuzz — block-based generation fuzzing Randall **complements** with coverage + stalking |
| **CANAPE** | Leg 6 — see the protocol before you fuzz it |
| **PaiMei / pStalker** | Leg 4 — coverage novelty, crash stalking, color-coded path maps (see README stalking diagram) |
| **Boo** | The innocent input that still finds the bug (your seed corpus) |

---

## Eight legs

Randall has eight legs — eight feature areas. See [LEGS.md](LEGS.md) for the learning path.

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
