# Product maturity — what’s finished vs what’s still lab

Randfuzz is a **serious indie fuzzer** with a clear niche (semantic oracles + AI-code hunting + session-aware generation). It is **past toy**, and **not yet** a default industry replacement for AFL++/libFuzzer.

This doc expands the unfinished surface into concrete gaps, done criteria, and polish priorities. Lore/mascot stay; product honesty here.

| Tier | Meaning |
|------|---------|
| **Solid** | Ships, documented, used in lab smoke |
| **Capable** | Works; confidence / UX / packaging still thin |
| **Lab** | Demo / heuristic / placeholder — do not sell as production-ready |
| **Missing** | Not built (or intentionally deferred) |

---

## Snapshot

| Area | Tier | One-line status |
|------|------|-----------------|
| Generation + mutators + sessions | Solid | Block models, havoc, dictionaries, flows |
| Coverage stalking (DynamoRIO) | Capable | Works Win/Linux when installed; no SanCov-native default |
| Crash triage / scream canisters | Capable | Capture + dedup + guides; exploit path stops at offsets |
| Oracle engine | Capable | Auth/state/structure/resource rules; still rule-authored |
| Bug Hunter attribution | Lab | Marker-strong; style heuristic weak — not ground truth |
| Mistake catalog + arming | Capable | OWASP/AISW-informed channels; needs more field feedback |
| Web (`http`/`https`) fuzz | Capable | Framing + status oracles + cookie jar stub; not a full web scanner |
| Lab targets (vuln*) | Lab | Teaching crashes, not market parsers |
| File templates (`file-text` / `file-framed`) | Capable | In-repo mini-parsers + seeds; still teaching-floor depth |
| AFL++ / honggfuzz adapters | Capable | Real campaigns + corpus sync; bake-off scaffold in BENCHMARKS |
| Packaging (`pack` / standalone) | Capable | Host RID pack + win/linux scripts; no signed installer yet |
| Serve / agent security | Capable | Token required on LAN bind; no users/roles/TLS termination |
| Multi-tenant / SaaS | Missing | Single-box lab tool by design today |
| Head-to-head benchmarks | Lab | Scaffold + script; results table empty until you run it |
| Automated test suite | Capable | `tests/Randall.Tests` covers LabAccess, HTTP, Magician, paths |
| L2–L4 packet forge | Missing | Phase 24 — deferred on purpose |

Related: [ROADMAP.md](ROADMAP.md) · [BUG_HUNTER.md](BUG_HUNTER.md) · [ENGINE_ADAPTERS.md](ENGINE_ADAPTERS.md) · [LAB_AGENT.md](LAB_AGENT.md)

---

## 1. Heuristic attribution (Bug Hunter)

**What works today**
- High confidence: `BEGIN AI` / `END AI`, `BEGIN HUMAN`, tool markers (Copilot/Cursor/…)
- Hunt plan + oracle/dictionary arming from suggested mistake classes
- Reports under `corpus/_bug_hunter/`

**Still lab**
- Whole-file “style” scoring (comment density, TODOs) is a weak prior — easy false positives
- No AST / embedding / PR-blame integration
- No calibration set (precision/recall on labeled AI vs human trees)
- Unknown blocks dominate on unmarked corporate codebases

**Done when**
- Annotated regions remain the primary path; style signals stay capped **low** and labeled as such
- Reports show **confidence tier** (high / medium / low) + an explicit limitations section
- Optional: import from git blame / CODEOWNERS / CI “AI authored” labels
- Optional: eval fixture under `examples/` with scored expected attributions

**Polish shipped here:** attribution markdown includes tiers + limitations; style confidence is capped so it cannot look like annotations.

---

## 2. Demo-ish targets

**What works today**
- Rich **teaching floor**: vulnserver, VulnHttp/Ftp/Ssh/Tftp/Rpc/Smb, VulnLab mitigation ladder, harness demos
- Recipe catalog for starting shapes
- Cross-platform lab build scripts

**Still lab**
- Stock network targets (vuln*) remain intentionally crashable toys — great for onboarding
- file-text / file-framed are **mini-parsers** (in-repo), not market formats — pair with ReelDeck for deeper file stalking

**Done when**
- At least 2–3 **non-toy** example projects (oss parser or in-repo mini-parser with documented bugs) — **ReelDeck + file-text + file-framed shipped**
- Templates ship with a tiny in-repo parser so `doctor`/`fuzz` work out of the box — **yes**
- README “first crash in 5 minutes” path does not depend on Windows-only vulnserver lore — **file-text / ReelDeck**

**Polish shipped here:** `targets/file-text`, `targets/file-framed`, Win/Linux builders, dictionaries, crash seeds.
---

## 3. Enterprise polish (auth, multi-tenant, packaging)

### Auth / agent exposure
**Was:** `randall agent` on `0.0.0.0` with open `/api/*` on the LAN.

**Now:** shared secret `RANDALL_AGENT_TOKEN` (or `--token`) — Bearer / `X-Randall-Token`. Health stays open; mutating APIs require the token when set. UI can store a token for remote agent proxying. **LAN harden:** `randall agent` (default bind `0.0.0.0`) **refuses to start** without a token. Escape hatch: `--allow-open` (prints WARN). Localhost `serve` stays open by default.

**Still missing**
- Per-user accounts, roles, audit log
- TLS termination / reverse-proxy recipes as first-class
- mTLS or short-lived tokens

### Multi-tenant
**Missing by design for now.** One process, one `data/` tree, flat JSON/JSONL. SaaS would need workspaces, isolation, quotas — a different product shape.

### Packaging
**Capable:** `randall pack` / `publish-standalone` folder.

**Still thin**
- No Authenticode / Linux package signing
- DynamoRIO / AFL++ still manual sidecar installs
- No “single zip that includes lab targets + tools” SKU

**Done when:** tagged release artifacts + one-page install that matches README for Win and Linux.

**Polish shipped here:** `randall pack --rid` (host default), `scripts/publish-standalone.sh`, [RELEASE.md](RELEASE.md).
---

## 4. Benchmarks vs AFL++ / libFuzzer

**What works today**
- Optional `fuzz.engine: aflpp|honggfuzz` with crash/corpus sync
- `randall stalk bench` compares **Randfuzz profiles** (basic/fuzz/fuzzier), not external engines

**Still missing**
- Shared harness suite numbers filled into the results table
- Published table with exec/s, unique crashes, edges, wall time on a quiet box
- Honest positioning copy in README (“we win on X; they win on Y”) — scaffold copy lives in BENCHMARKS

**Done when**
- `docs/BENCHMARKS.md` + `scripts/bench-engines.sh` on Linux CI (nightly OK) — **scaffold shipped**
- Results checked in or linked; no claim of “next-gen” without numbers

**Positioning until then:** Randfuzz owns **structure + sessions + oracles + triage UX**; AFL++ owns **raw coverage throughput**. Use adapters when you need both.
---

## 5. Other unfinished product muscle

| Gap | Why it matters | Next polish |
|-----|----------------|-------------|
| Automated unit/integration tests | Regressions only caught by smoke | **Expanded:** Nbss, kinds, loader, dict, matcher, oracle, cookies, doctor hints + Linux CI |
| Linux coverage without DynamoRIO | Many labs won’t install DR | SanitizerCoverage / perf backend (roadmap note in STALKING) |
| Web fuzz depth | Not ZAP/Burp | **Cookie jar stub shipped**; OpenAPI import deferred; richer status/body oracles next |
| Oracle authoring UX | Rules are YAML-expert today | Scare Floor / UI rule builder for common auth/state patterns |
| Attribution → seed synthesis | Plan suggests; doesn’t always mint seeds | Auto-seed from mistake channel=seed classes |
| Phase 24 L2–L4 forge | Scapy-class surface | Keep deferred until app-PDU path is the default habit |

---

## 6. Windows vs Linux — do we port everything?

**Short answer: no.** Maturity means **parity where the product promise is cross-platform**, and **honest OS-native counterparts** where the underlying tool is OS-bound. Blindly rewriting Linux-only engines for Windows wastes effort and usually ships a worse adapter.

| This-week feature | Runs on | Windows action |
|-------------------|---------|----------------|
| Oracle / Bug Hunter / mistake catalog | Win + Linux (.NET) | None — already shared |
| Magician / Joker | Win + Linux (.NET) | None — already shared |
| Web HTTP fuzz + notifications + AI seed | Win + Linux | None — already shared |
| Lab agent token / serve gate | Win + Linux | None — already shared |
| DynamoRIO stalking | Win + Linux (when installed) | Already had Windows; Linux install was the gap |
| ReelDeck + path stalking | Win + Linux (native C) | **Build script parity** (`build-reeldeck.ps1`) — not a rewrite |
| AFL++ / honggfuzz adapters | **Linux only** | **Do not port.** Keep as optional Linux grinders; Windows stays on Randfuzz engine (+ future WinAFL only if product asks) |
| AFL `FORKSRV_FD` shim | **Linux only** | **Do not port.** Windows already uses warm stdio workers |
| Linux core / gdb / ASan triage | Linux | Already have WinDbg / minidump / Page Heap counterparts |
| Sysinternals / ETW / pktmon | Windows | Keep Windows-only; Linux uses strace/tcpdump/perf |

**Polish rule**
1. Shared C# engine features → one codebase (already).
2. Native lab targets → ship **both** `.sh` and `.ps1` builders when the target is part of the demo story (ReelDeck, file-text, file-framed).
3. External Linux engines → document as Linux adapters; never claim Windows AFL++ inside Randfuzz.
4. Triage tooling → pair by *role* (dump/trace/heap), not by cloning every binary.

Related install notes: [INSTALL_WINDOWS.md](INSTALL_WINDOWS.md) · [INSTALL_LINUX.md](INSTALL_LINUX.md) · [ENGINE_ADAPTERS.md](ENGINE_ADAPTERS.md).

---

## Priority order (product maturity)

1. **Honesty in-product** — confidence tiers, doctor warnings, maturity links (this doc)
2. **Agent token required on LAN** — refuse `0.0.0.0` without `--token` (**shipped**; `--allow-open` escape)
3. **Out-of-box file demos** — ReelDeck + file-text + file-framed builders on Win/Linux (**shipped**)
4. **Engine bake-off scaffold** — `docs/BENCHMARKS.md` + `scripts/bench-engines.sh` (**shipped**; fill numbers)
5. **Automated tests** — LabAccess, HTTP, Magician, path coverage (**expanding**)
6. **Release packaging** — RID-aware pack + [RELEASE.md](RELEASE.md) (**scaffold**)
7. **Attribution upgrades** — blame/CI labels before heavier ML
8. **No fake Windows ports** of AFL++/forksrv — document adapters instead

---

## What “finished enough” means for the niche

Ship as **the chameleon stack for semantic + AI-code campaigns**, not as a drop-in AFL++ killer:

- Oracle judges behavior; Bug Hunter arms the hunt
- Sessions/models beat blind bytes on protocols
- External engines grind coverage when needed
- Randall theme stays for identity; CLI/API stay plain for outsiders

When the table above is mostly **Solid/Capable** and benchmarks exist, drop the “lab” disclaimer from the README hero — not before.
