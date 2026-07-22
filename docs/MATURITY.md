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
| Web (`http`/`https`) fuzz | Capable | Framing + status oracles; not a full web scanner |
| Lab targets (vuln*) | Lab | Teaching crashes, not market parsers |
| File templates (`file-text` / `file-framed`) | Lab | Placeholders — user must bring real exe + seeds |
| AFL++ / honggfuzz adapters | Capable | Real campaigns + corpus sync; not a bake-off harness suite |
| Packaging (`pack` / standalone) | Capable | Folder publish exists; no signed installer / versioned releases story |
| Serve / agent security | Lab → Capable | Optional token gate now; no users/roles/TLS termination |
| Multi-tenant / SaaS | Missing | Single-box lab tool by design today |
| Head-to-head benchmarks | Missing | No published corpus/crash/edge bake-off vs AFL++/libFuzzer |
| Automated test suite | Missing | Build + smoke = CI; no xunit matrix |
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
- Stock targets are intentionally crashable toys — great for onboarding, weak as “we fuzz real products” proof
- `file-text` / `file-framed` are templates pointing at missing/generic exes
- Few public **real-format** profiles (PNG, JSON, protobuf, …) with golden seeds + known bugs

**Done when**
- At least 2–3 **non-toy** example projects (oss parser or in-repo mini-parser with documented bugs)
- Templates ship with a tiny in-repo parser so `doctor`/`fuzz` work out of the box
- README “first crash in 5 minutes” path does not depend on Windows-only vulnserver lore

---

## 3. Enterprise polish (auth, multi-tenant, packaging)

### Auth / agent exposure
**Was:** `randall agent` on `0.0.0.0` with open `/api/*` on the LAN.

**Now (first polish):** optional shared secret `RANDALL_AGENT_TOKEN` (or `--token`) — Bearer / `X-Randall-Token`. Health stays open; mutating APIs require the token when set. UI can store a token for remote agent proxying.

**Still missing**
- Per-user accounts, roles, audit log
- TLS termination / reverse-proxy recipes as first-class
- mTLS or short-lived tokens
- Hard fail when binding `0.0.0.0` without a token (today: warn)

### Multi-tenant
**Missing by design for now.** One process, one `data/` tree, flat JSON/JSONL. SaaS would need workspaces, isolation, quotas — a different product shape.

### Packaging
**Capable:** `randall pack` / `publish-standalone` folder.

**Still thin**
- No versioned GitHub Releases cadence called out in-product
- No signed Windows installer / Linux package
- DynamoRIO / AFL++ still manual sidecar installs
- No “single zip that includes lab targets + tools” SKU

**Done when:** tagged release artifacts + one-page install that matches README for Win and Linux.

---

## 4. Benchmarks vs AFL++ / libFuzzer

**What works today**
- Optional `fuzz.engine: aflpp|honggfuzz` with crash/corpus sync
- `randall stalk bench` compares **Randfuzz profiles** (basic/fuzz/fuzzier), not external engines

**Still missing**
- Shared harness suite (same entrypoint, same seeds, same time budget)
- Published table: exec/s, unique crashes, edges, wall time — Randfuzz vs AFL++ vs libFuzzer/honggfuzz
- Honest positioning copy in README (“we win on X; they win on Y”)

**Done when**
- `docs/BENCHMARKS.md` + `scripts/bench-engines.sh` on Linux CI (nightly OK)
- Results checked in or linked; no claim of “next-gen” without numbers

**Positioning until then:** Randfuzz owns **structure + sessions + oracles + triage UX**; AFL++ owns **raw coverage throughput**. Use adapters when you need both.

---

## 5. Other unfinished product muscle

| Gap | Why it matters | Next polish |
|-----|----------------|-------------|
| No automated unit/integration tests | Regressions only caught by smoke | Start with attribution + oracle + HTTP framing tests |
| Linux coverage without DynamoRIO | Many labs won’t install DR | SanitizerCoverage / perf backend (roadmap note in STALKING) |
| Web fuzz depth | Not ZAP/Burp | Auth cookie jars, OpenAPI import, richer status/body oracles |
| Oracle authoring UX | Rules are YAML-expert today | Scare Floor / UI rule builder for common auth/state patterns |
| Attribution → seed synthesis | Plan suggests; doesn’t always mint seeds | Auto-seed from mistake channel=seed classes |
| Phase 24 L2–L4 forge | Scapy-class surface | Keep deferred until app-PDU path is the default habit |

---

## Priority order (product maturity)

1. **Honesty in-product** — confidence tiers, doctor warnings, maturity links (this doc)
2. **Agent token by default on LAN** — warn → eventually require token when bind ≠ loopback
3. **One real-format demo project** — out-of-box crash with golden seed
4. **Engine bake-off script** — numbers or silence on “beats AFL++”
5. **Minimal test project** — lock Oracle + Bug Hunter + HTTP framing
6. **Release packaging** — tagged standalone + install docs parity
7. **Attribution upgrades** — blame/CI labels before heavier ML

---

## What “finished enough” means for the niche

Ship as **the chameleon stack for semantic + AI-code campaigns**, not as a drop-in AFL++ killer:

- Oracle judges behavior; Bug Hunter arms the hunt
- Sessions/models beat blind bytes on protocols
- External engines grind coverage when needed
- Randall theme stays for identity; CLI/API stay plain for outsiders

When the table above is mostly **Solid/Capable** and benchmarks exist, drop the “lab” disclaimer from the README hero — not before.
