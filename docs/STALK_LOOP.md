# The stalk loop — baseline → fuzz → learn → repeat

**Hands-on checklist for your own app:** [HOWTO_STALK_GENERIC_APP.md](HOWTO_STALK_GENERIC_APP.md) (Help → Getting started).  
**Color coverage in IDA / Ghidra:** [HOWTO_STALK_IDA_GHIDRA.md](HOWTO_STALK_IDA_GHIDRA.md).

This is the research process Randfuzz is built around (same idea as PaiMei Pstalker / your fuzzing cheat sheet).

**You only find bugs in code that actually runs.**  
So you measure what “normal” touches, then keep mutating until new code (and crashes) show up — and you study those crashes until you understand them.

---

## One rule (read this first)

Do the **whole loop on the machine that runs the target binary**.

| Where you work | What you get |
|----------------|--------------|
| **Lab VM** with `randall agent` (or local `randall serve` on that box) | Coverage layers, dumps, memory lens, crashes — the full stalk loop |
| **Laptop** only driving `target.agentUrl` | Can start/stop the remote process — **not** a full coverage stalk or reliable remote dumps |

Think Sulley: procmon + crashbin lived **on the target host**; you copied the crashbin home later.  
Same here: stalk + fuzz **on the lab**, then optionally **pull a crash pack** to the laptop.

Open the lab console at `http://<lab-ip>:5000` (badge: **Remote lab**) when the binary lives on a VM.

---

## What you’re repeating

```text
┌─────────────────────────────────────────────────────────────┐
│  0. Snapshot the VM                                         │
└───────────────────────────┬─────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  1. BASELINE — use the app normally under coverage          │
│     Record a "baseline" layer (your happy-path blocks)      │
└───────────────────────────┬─────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  2. FUZZED — basic fuzz campaign                            │
│     Record a "fuzzed" layer · look at novel blocks          │
└───────────────────────────┬─────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  3. FUZZIER — better seeds / mutators / scare recipes       │
│     Record "fuzzier" (or another custom tag) · compare      │
└───────────────────────────┬─────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  4. CRASH — when it dies, study it (dump + memory lens)     │
│     Auto "crash" layer · triage · understand · adjust       │
└───────────────────────────┬─────────────────────────────────┘
                            ▼
              go back to 2 or 3 as many times as you want
```

Each pass answers: *What new code did I hit? What did I still miss? Why did it crash?*

---

## Step 0 — Snapshot

On the lab VM: take a clean snapshot before you start.  
After the stack works once, take another (“known good Randfuzz lab”).  
If a campaign trashes the box, roll back — don’t fight a dirty lab.

---

## Step 1 — Baseline (record normal use)

**Goal:** a coverage map of “I used the program the way a user would.”

### Option A — Long-lived network target (Vulnserver-style)

1. Start Target Runtime / lab so the app is listening  
   (`Fuzz → Lab servers` / `randall runtime start -c projects/….yaml`).
2. Prefer coverage on: project YAML `fuzz.coverageGuided: true` and DynamoRIO installed when you can (`fuzz.stalkMode: auto` or `external`).
3. **Use the app yourself** — browser, client, happy-path commands — whatever normal traffic looks like.
4. Stop when done. Capture a drcov log if you ran under DynamoRIO manually, **or** let a short coverage-guided run with “normal” seeds create corpus edges.
5. Open **Stalking bugs**:
   - Project = your target  
   - **Start baseline session** (Windows: Procmon + Sysinternals · Linux: `ss` + `/proc` maps) → use the app naturally → **Stop + record** (auto-attaches Target Runtime PID when available)  
   - Or: Tag = **baseline**, leave **Mini-timeline each layer** checked, **Record layer** / **From corpus edges**  
   - Review **Exploit Surface** findings and **Surface fuzz ideas**

That layer is your “green” / normal map — code you already know how to reach — plus host
mini-timeline and Exploit Surface suggestions (see [MINI_TIMELINE.md](MINI_TIMELINE.md) ·
[SURFACE.md](SURFACE.md)).
Record the same way for **fuzzed** / **fuzzier** / custom tags; then open **Host timeline compare**
and **Surface compare** to see what changed between phases.

### Option B — File-format target

Run the parser once on a few valid files under coverage, then record **baseline** from that drcov / corpus edges the same way.

---

## Step 2 — Basic fuzz (`fuzzed`)

**Goal:** throw simple mutations and see what *new* blocks appear vs baseline.

1. **Scare Floor / Campaign** — start with default mutators and existing seeds (or a small dictionary).
2. Run a campaign on the **same lab console** (not laptop-only + agentUrl if you care about coverage).
3. When the run finishes (or mid-campaign when you have edges):
   - **Stalking bugs** → Tag = **fuzzed** → **From corpus edges** or **Record layer**
4. Look at **Compare** and **Block map**:
   - Shared with baseline = already known  
   - **Novel** = new code the basic fuzzer reached  

Crashes during this run also show under **Crashes** (dump + analysis + memory lens when available). Campaigns auto-add a **crash** stalk layer when a crash is saved.

---

## Step 3 — Advanced cases (`fuzzier`) — repeat

**Goal:** deliberately push into code the basic run missed (your cheat’s “modify fuzzer to cover more code”).

1. Inspect novel / missed blocks (PDF: white in IDA after yellow baseline + green fuzzed):
   - **Stalking bugs → Missed blocks** (why + ranked fuzz ideas), or  
   - `randall stalk missed -p <project>`  
   - Export IDC/Ghidra (**oldest first** — only paints still-uncolored), or one-shot:  
     `randall stalk dynapstalker <drcov.log> <exe> out.idc --color 0x00ffff`  
     `randall stalk dynapstalker <drcov.log> <exe> out.py --format ghidra --color 0x00ffff`  
   - Optional: import a BB inventory for never-hit without IDA  
     (`randall stalk inventory -p <project> --import blocks.txt`)  
   - Prefer white/missed near string copies / `rep movs*` / error handlers.
2. Improve the attack surface using the tips:
   - **Scare Floor** — richer recipes, multi-step sessions, better dictionaries  
   - Session graph / protocol model (session-unexplored forks)  
   - Mutator weights, max size, coverage-guided on  
   - `target.postStart` if the app needs priming / UI open  
3. Run another campaign.
4. Record a new layer: Tag = **fuzzier** (label it `round-2 smb write` etc. — you can record **as many fuzzier layers as you want**).
5. Compare again + re-open **Missed blocks**: baseline vs fuzzed vs fuzzier — *what’s still dark?*

Repeat step 3 forever. Each round is a new layer, not a wipe.

---

## Step 4 — Crash → learn (stalk the bug)

When it crashes, don’t only save the input — **understand the death**.

| Tool | What it’s for |
|------|----------------|
| **Crashes** tab | Input, triage class, fault address, cluster |
| **Memory lens** | Fill patterns, UAF hints, heap / neighborhood |
| `randall analyze -i <guid>` | Registers, exception, modules |
| `randall memory -i <guid>` | Same lens from CLI |
| Debugger (`wait` / open dump) | Sit on the fault like Immunity/WinDbg in the old flow |
| Stalk **crash** layer | Which blocks were hot on the way down |

Then ask: *Did I hit a new path? Is this exploitable research-wise? What seed would go deeper?*  
Feed that back into step 3.

---

## Where things live (on the lab machine)

| Data | Path |
|------|------|
| Stalk layers | `data/stalk/<project>/` |
| Crashes, dumps, lens | `data/crashes/<project>/` |
| Run journals | `data/runs/<runId>/` |
| Corpus / edges | project corpus dir (often under project or `data/`) |

### Take results home (offline)

After a session on the lab:

```powershell
# On laptop (or any other console)
randall crashes pull -a http://<lab-ip>:5000 -p <project> --import
```

Or **Bundles → Pull from remote agent**.  
That brings dumps + lens + crash index. Stalk layer zips are still under `data/stalk/` on the lab — copy that folder or export IDC/Ghidra from the lab UI if you want the color maps offline too.

---

## UI map (click path)

| You want… | Go here |
|-----------|---------|
| Start/stop target | **Fuzz → Lab servers / Target Runtime** |
| Build smarter cases | **Fuzz → Scare Floor** |
| Run a campaign | **Fuzz → Campaign** (on the lab host) |
| Natural-use baseline session | **Stalking bugs → Start baseline session** / Stop + record |
| Record baseline / fuzzed / fuzzier | **Stalking bugs → Add layer** |
| Host surface (sideload / listen) | **Stalking bugs → Exploit Surface** (+ Surface fuzz ideas) |
| See what changed (coverage) | **Stalking bugs → Compare / Block map** |
| See what changed (host) | **Stalking bugs → Host timeline compare / Surface compare** |
| Why still dark + how to fuzz | **Stalking bugs → Missed blocks** (`randall stalk missed`) |
| Study a crash | **Crashes** (+ Memory lens) |
| Color IDA / Ghidra | **Stalking bugs → Export** |
| Backup dumps home | **Bundles → Crash artifact pack** |

Help tab also serves this doc and [STALKING.md](STALKING.md) (API/CLI reference).

---

## Mental model vs the old tools

| Your cheat / Sulley / PaiMei | Randfuzz |
|------------------------------|----------|
| Use app under Pstalker “normal” tag | **baseline** layer |
| Run http.py fuzzer → “fuzzed” | Campaign + **fuzzed** layer |
| Modify script → “fuzzier” | Better seeds/mutators + **fuzzier** layer |
| crashbin → explorer | **Crashes** + memory lens + analyze |
| Copy crashbin to another PC | **Crash artifact pack** pull/import |
| Export IDC colors to IDA | **Export → IDA IDC / Ghidra** |

---

## Short checklist

- [ ] Snapshot lab  
- [ ] Work in lab console (`serve` local or `agent` Remote lab)  
- [ ] Baseline session (or normal use → record **baseline**) → review Exploit Surface  
- [ ] Basic campaign → record **fuzzed** → compare novel blocks + surface  
- [ ] Improve cases → campaign → record **fuzzier** → compare (repeat)  
- [ ] On crash: lens + debugger + learn → feed next round  
- [ ] Optional: pull crash pack to laptop when done  

That’s the process. The loop never “finishes” — you stop when you’ve learned enough or the delta stops growing.
