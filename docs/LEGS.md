# Randall's Eight Legs — Learning the Fuzzer

Randall Boggs has many legs. Each leg is a **feature area** and a **lesson** in vulnerability research. Work through them in order when learning the tool, or jump to the leg you need.

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

## Leg 1 — Model (Protocol grammar)

**Learn:** How generation fuzzers describe valid-ish inputs.

**Randall concept:** Blocks, primitives (static, string, group, random), nested structures.

**Legacy parallel:** Sulley/Boofuzz `s_initialize` / `s_block`.

**Exercise:** Define a simple TCP packet: 4-byte length + message type + payload.

---

## Leg 2 — Mutate (Breaking things intelligently)

**Learn:** Mutation is not random noise — it's guided destruction.

**Randall concept:** Field-aware mutations, boundaries, patterns, session-aware state.

**Exercise:** Mutate only the length field; observe how parsers fail differently than mutating payload bytes.

---

## Leg 3 — Send (Transports)

**Learn:** Getting bytes to the target — network, file, stdin.

**Randall concept:** `ITransport` — TCP, UDP, MITM proxy, file drop, process stdin.

**Legacy parallel:** CANAPE in-stream injection; Boofuzz `SocketConnection`.

**Exercise:** Replay a captured packet to a local service.

---

## Leg 4 — Stalk (Coverage)

**Learn:** Not all inputs are equal — prioritize inputs that reach **new code**.

**Randall concept:** DynamoRIO drcov, edge bitmap, corpus ranking by novelty.

**Legacy parallel:** PaiMei Process Stalker (modern instrumentation, not breakpoints).

**Exercise:** Run a target under drcov; compare two inputs — which hit new basic blocks?

---

## Leg 5 — Scream (Crashes)

**Learn:** A crash is a data object — input + path + signature + dump.

**Randall concept:** `CrashRecord`, stack hash dedup, minidump, replay in one command.

**Exercise:** Crash a test binary; deduplicate two crashes that are the same bug.

---

## Leg 6 — Proxy (CANAPE-style analysis)

**Learn:** See the protocol before you fuzz it.

**Randall concept:** MITM capture, hex view, parse tree, inject/fuzz from the pipeline.

**Legacy parallel:** James Forshaw's CANAPE — Burp Suite for binary protocols.

**Exercise:** Intercept traffic, edit one field live, replay.

---

## Leg 7 — Web (Operate anywhere)

**Learn:** Fuzzing UIs help you *understand* what's happening.

**Randall concept:** `randall serve` — browser dashboard, live corpus/crash feed (SignalR).

**Exercise:** Start the server; watch coverage and crashes update in the browser.

---

## Leg 8 — Pack (Standalone portability)

**Learn:** Lab tools must move — laptop, VM, air-gapped box.

**Randall concept:** Self-contained publish, SQLite corpus, project bundles (`export` / `import`).

**Exercise:** Zip a project folder; run on an offline Windows VM with no install step.

---

## Putting it together

The full Randall loop:

```
Capture or craft seed → Model → Mutate → Send → Stalk (coverage?)
    → New edges? Keep. → Crash? Scream + dedup → Export to Ghidra/Dragon Dance
```

When all eight legs work together, you're doing what Sulley + pStalker + CANAPE did — in one maintained, portable tool.
