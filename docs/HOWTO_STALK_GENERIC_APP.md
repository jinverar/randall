# How to: stalk a generic application

A checklist you can follow end-to-end for **your own** Windows app (not only lab targets).  
Do this when you have time — every step says what to click or run.

**Related:** [STALK_LOOP.md](STALK_LOOP.md) (why) · [CUSTOM_TARGETS.md](CUSTOM_TARGETS.md) (YAML) · [TARGET_RUNTIME.md](TARGET_RUNTIME.md) (process ownership)

---

## Before you start

| Need | Notes |
|------|--------|
| App under test | Your `.exe` (or a service you start yourself) |
| How you talk to it | TCP / UDP port, **or** file path argument |
| At least one valid sample | A real request, file, or capture you know works |
| Lab machine | Prefer a **VM with a snapshot** — run Randfuzz **on that same machine** as the binary |
| Optional but better | DynamoRIO (`DYNAMORIO_HOME`) for full basic-block coverage |

**Rule:** open the console on the machine that runs the binary (`randall serve` locally, or `randall agent` and browse to `http://<lab-ip>:5000`).

```powershell
# On the lab machine (from repo root)
dotnet run --project src/Randall.Cli -- serve --port 5000
# or, reachable from your laptop browser:
dotnet run --project src/Randall.Cli -- agent --port 5000
```

---

## Phase A — Register your app as a Target profile

### A1. Create the project

**UI (easiest)**

1. Open the console → **Fuzz → Scare Floor** (case recipes).
2. Under **Create new target**, pick:
   - **TCP** or **UDP** if it listens on a port  
   - **File format** if it parses a file (`{file}` arg)
3. Set **name** (this becomes the Target profile), host/port or exe path.
4. Save — YAML lands under `projects/local/<name>.yaml` (gitignored).

**CLI alternative**

```powershell
randall case new --name myapp --kind tcp --host 127.0.0.1 --port 9999
# edit projects/local/myapp.yaml — set target.executable to your .exe
```

### A2. Point at your binary (long-lived network apps)

Edit the YAML so Target Runtime owns the process:

```yaml
name: myapp
kind: tcp
target:
  executable: C:/path/to/your/app.exe   # or relative to the YAML
  args: []                               # whatever your app needs
  longLived: true
  timeoutMs: 5000
  pageHeap: false                        # true later if you have Debugging Tools
  postStart:
    - op: wait-port
      host: 127.0.0.1
      port: 9999
      timeoutMs: 8000
transport:
  type: tcp
  host: 127.0.0.1
  port: 9999
fuzz:
  maxIterations: 300
  coverageGuided: true
  stalkMode: auto                        # DynamoRIO if present, else native
  debuggerMode: wait                     # scream dumps on crash
  corpusDir: ../data/corpus/myapp
  crashesDir: ../data/crashes/myapp
mutators:
  - bitflip
  - havoc
  - dictionary
  - expand
seeds:
  - seeds/myapp_seed.bin
```

Template to copy: `docs/templates/tcp-runtime.yaml`.

### A3. Smoke-test start/stop

1. **Fuzz → Lab servers → Target Runtime** → refresh (or CLI below).
2. Start the project:

```powershell
randall runtime start -c projects/local/myapp.yaml
randall runtime
randall runtime stop myapp
```

Confirm the app listens and you can talk to it with a normal client.

---

## Phase B — Baseline (record normal use)

**Goal:** a coverage layer of “I used the app like a user.”

1. Snapshot the VM (optional but smart).
2. Start the app via Target Runtime (A3).
3. **Use it yourself** for a few minutes — every menu, happy-path command, login, file open, etc. that you care about.
4. If you can run under DynamoRIO manually for a cleaner baseline:

```powershell
# Example shape — adjust paths to your DynamoRIO + app
drrun.exe -t drcov -dump_text -- C:\path\to\your\app.exe
# use the app, then exit; note the drcov.*.log path
```

5. Open **Stalking bugs**:
   - **Project** = `myapp`
   - **Tag** = `baseline (normal use)`
   - **Label** = e.g. `manual happy path`
   - **drcov log path** = that log (if you have one)  
     — or leave empty and click **From corpus edges** after a short coverage run with only valid seeds
   - Click **Record layer**

You should see one baseline layer with a non-zero block count.

---

## Phase C — Basic fuzz (`fuzzed`)

**Goal:** simple mutations; see what *new* code appears.

1. **Scare Floor** — upload or build one valid seed → **Save as seed**.
2. Enable basic mutators (`bitflip`, `havoc`; add `dictionary` if you saved tokens).
3. **Fuzz → Campaign** → select `myapp` → modest iterations (e.g. 200–500) → **Start**.
4. Watch the **live log**. When it finishes (or after a solid run):
   - **Stalking bugs** → Tag = `fuzzed` → Label = `round-1 basic` → **From corpus edges** (or Record layer).
5. Open **Compare** / **Block map** — note **novel** blocks vs baseline.

If it crashes: leave it — go to Phase E, then come back.

---

## Phase D — Advanced rounds (`fuzzier`) — repeat as often as you want

**Goal:** push into code the basic run missed.

Each round:

1. Look at novel / still-dark areas (Compare, **Export → IDA IDC / Ghidra**, or the full tutorial [HOWTO_STALK_IDA_GHIDRA.md](HOWTO_STALK_IDA_GHIDRA.md)).
2. Improve cases on **Scare Floor** (richer recipes, multi-step session, dictionary tokens, bigger sizes).
3. Run Campaign again (more iterations / coverage-guided on).
4. **Stalking bugs** → Tag = `fuzzier` → Label = `round-2 …` → **From corpus edges**.
5. Compare again. Repeat D until the delta shrinks or you’re done for the day.

There is no limit on how many `fuzzier` layers you record.

---

## Phase E — When it crashes (learn, don’t skip)

1. **Crashes** tab → open the crash.
2. Read triage + **Memory lens** (fill/UAF/heap hints).
3. Optional CLI on the lab:

```powershell
randall analyze -i <crash-guid>
randall memory -i <crash-guid>
randall debug open -i <crash-guid> --kind windbg-preview
```

4. A **crash** stalk layer is usually auto-recorded — confirm under **Stalking bugs**.
5. Ask: new path? interesting fault? what seed would go deeper? → feed Phase D.

---

## Phase F — Stop / backup (optional)

On the lab:

```powershell
randall crashes pack -p myapp -o data/exports/myapp_artifacts.zip
```

On another machine later:

```powershell
randall crashes pull -a http://<lab-ip>:5000 -p myapp --import
# or import the zip: randall crashes unpack -i data/exports/myapp_artifacts.zip
```

UI: **Bundles → Crash artifact pack**.

Copy `data/stalk/myapp/` too if you want the color layers offline.

---

## Quick checklist (print / tick)

- [ ] Snapshot lab VM  
- [ ] Console open **on the lab** (`serve` or `agent`)  
- [ ] YAML Target profile for **my app** (`longLived` + exe if network)  
- [ ] `randall runtime start` works; I can use the app by hand  
- [ ] **Baseline** layer recorded  
- [ ] Basic campaign → **fuzzed** layer → looked at novel blocks  
- [ ] Improved seeds → campaign → **fuzzier** layer (repeat…)  
- [ ] Crashes studied (lens / analyze / debugger)  
- [ ] Optional: crash pack exported / pulled  

---

## Troubleshooting

| Problem | Try |
|---------|-----|
| No novel blocks | Coverage off — set `coverageGuided: true`, install DynamoRIO, or use `stalkMode: native` |
| App won’t stay up | `postStart` `wait-port`; check args; Target Runtime restart after crash |
| No dumps | Fuzz **on the lab**; `debuggerMode: wait`; don’t rely on laptop-only `agentUrl` |
| Empty baseline | Record after real use, or import a real drcov log path |
| Profile missing in UI | Check YAML `name:`; refresh; file under `projects/` or `projects/local/` |

When you’re ready, start at **Phase A** with your app’s real path and port.
