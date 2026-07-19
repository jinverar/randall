# Harness design principles

In-process and persistent harnesses only pay off if every iteration is a **meaningful, comparable** execution of the target. Violate these principles and coverage lies, crashes hide, and “persistent mode” becomes shared mutable garbage.

**One rule above all:** *let the target reject invalid input, not the harness.*

**Question most results.** High crash rates, sudden speedups, and “we found nothing” are all suspicious until you can explain them with the isolation mode and oracle in use.

---

## Isolation matrix (what Randfuzz actually does)

| `persistent` | `forkServer` | Managed behavior | Native worker behavior |
|--------------|--------------|------------------|------------------------|
| **true** (default in-process) | **true** (default = follow persistent) | Warm ALC; `Reset()` each case; **reload** after crash | Warm worker; **new worker** after AV/crash |
| **true** | **false** | Warm; `Reset()` each case; stay loaded after managed exception | Warm; still must respawn after native death |
| **false** | **false** | **Cold:** reload harness every case | **Cold:** new worker every case |
| **false** | **true** | Cold reload every case (forkServer alone does not keep state) | Cold worker every case |

YAML:

```yaml
fuzz:
  executionMode: in-process
  persistent: true          # null → true for in-process; false = cold
  forkServer: true          # null → same as persistent
  harnessStrict: true       # fail start if persistent without IInProcessHarnessReset
```

Out-of-process stdio: `persistent` / `forkServer` default **false** (null = off). Opt in for warm stdin protocol — see [PERSISTENT.md](PERSISTENT.md).

### Initialization / reset / shutdown

```text
Initialize()     once per harness load              → session state
     │
     ├─ Reset()  before every FuzzOne (persistent)  → clear iteration state
     ├─ FuzzOne(data)
     │  …
     └─ Shutdown()  when host unloaded              → release session state

Cold (persistent: false): Initialize → FuzzOne → Shutdown  every case
```

| Kind | Created | Cleared by |
|------|---------|------------|
| **Session state** | `Initialize()` | `Shutdown()` / ALC unload |
| **Iteration state** | during `FuzzOne` | **`Reset()`** (persistent) or process death (cold / native crash) |
| **Forbidden** | accidental statics | must move into Reset or disable persistent |

`fuzz.harnessStrict: true` → refuse persistent start without `IInProcessHarnessReset`.

---

## Anti-goals (do not build these)

| Anti-goal | Why it fails | What we do instead |
|-----------|--------------|--------------------|
| **Over-filter inputs in the harness** | Important paths become unreachable; coverage is about the filter | Target rejects; harness maps bytes only |
| **Hide crashes / errors** | Fuzzer optimizes for silence | Exceptions and non-zero returns surface as crashes; never catch-and-`return 0` |
| **Unintended persistent state** | Case N influences case N+1; false bugs / missed bugs | `Reset()` + cold mode + strict mode |
| **Poor reproducibility** | “Crash only after 10k iters” with leftover state | Cold isolation baseline; same seed + reset = same outcome |
| **Fuzzing at the wrong abstraction** | Harness reimplements protocol; fuzzer never hits real parser | Thin glue around the real entry (`parse`, `LLVMFuzzerTestOneInput`) |
| **Harness too restrictive** | Length clamps, magic checks, “valid only” gates | Honest reachability — every mutant reaches the target |
| **Ignore performance signals** | Hang, leak, or filter looks like “fast” | Track `avgFuzzOne`, resets, coldStarts, recycles; warn on outliers |
| **Trust results blindly** | Dictionary + bad oracle → crash spam; warm cache → fake exec/s | Question crash rate, recycle rate, and speed vs cold baseline |

---

## 1. Minimalism

The harness is glue, not a second product.

| Do | Don’t |
|----|--------|
| Load target, map bytes, call one entry, observe result | Reimplement parsing, protocol, or business logic |
| Thin wrapper around `parse()` / `LLVMFuzzerTestOneInput` | Multi-step scenarios, retries, “smart” repair |
| Prefer one call site | Optional paths that skip the target |

If the harness is interesting, it is too big.

---

## 2. Honest reachability

Every byte the fuzzer emits must be able to reach the target’s code under test.

- Do **not** drop, clamp, or rewrite inputs before the target sees them (except a documented, fixed mapping — principle 3).
- Do **not** `if (data.Length < N) return 0;` to “avoid” calling the target — that is the harness rejecting input.
- Coverage and crashes must reflect **target** behavior, not harness filters.

---

## 3. Controlled input mapping

If you must reshape bytes (e.g. length prefix, struct layout), the mapping is:

1. **Fixed** — same rule every iteration  
2. **Documented** — in harness comments / README  
3. **Non-filtering** — mapping never discards a case; at worst it produces a deterministic structure the target then rejects  

Example: `header = size; body = data` is controlled mapping.  
Example: “skip if not valid UTF-8” is **dishonest** filtering — pass the bytes; let the target fail.

---

## 4. No persistent side effects

After `Reset()` (or process recycle), the next `FuzzOne` must not see leftovers from the previous case.

| Side effect | Fix |
|-------------|-----|
| Static / singleton caches | Clear in `Reset()` or don’t use |
| Open files, sockets, temp paths | Close in `Reset()`; prefer per-iteration locals |
| Global RNG seed advanced across cases | Reseed in `Reset()` from a fixed seed if needed |
| Process-wide env / cwd changes | Avoid; restore in `Reset()` |
| Thread pools with queued work | Drain / don’t queue across iterations |

**Persistent mode** keeps the *process* warm; it must **not** keep *case state* warm.

---

## 5. Crash transparency

When the target faults, Randfuzz must see it.

| Signal | Meaning |
|--------|---------|
| Managed **exception** from `FuzzOne` | Crash / fault — saved as a crash |
| Native **AV / worker death** | Crash — worker recycled when warm / forkServer |
| Return **0** | Normal completion (**including** target rejecting input) |
| Return **non-zero** | Explicit harness abort signal (use sparingly; prefer throw for real faults) |

Do **not** catch-and-swallow target exceptions inside the harness. Do **not** translate crashes into `return 0`.

---

## 6. Determinism

Same input → same control flow and result (given the same reset state).

- No wall-clock deadlines inside the harness (use the fuzzer’s timeout).  
- No random choices in the harness.  
- No dependence on iteration index, PID, or “first call” flags that survive `Reset()`.  
- If the target is nondeterministic, document it — don’t add more.

---

## 7. Single responsibility — right abstraction

| Layer | Job |
|-------|-----|
| **Fuzzer** | Mutate, schedule, save crashes, coverage |
| **Harness** | Init once, reset per case, map bytes, call target, surface faults |
| **Target** | Accept / reject / parse / crash |

Fuzz at the **library / parser entry** you care about — not a mock of that entry inside the harness. Network daemons belong in out-of-process Target Runtime, not a fake socket loop in `FuzzOne`.

---

## 8. Performance signals (do not ignore)

Randfuzz reports harness stats every ~50 cases and at session end:

```text
cases=… crashes=…(rate) resets=… coldStarts=… recycles=…(rate)
avgFuzzOne=…ms max=…ms avgReset=…ms
```

| Signal | Question |
|--------|----------|
| `avgFuzzOne` jumps 20× | Hang, deadlock, pathological input, or accidental I/O? |
| `recycleRate` high (native) | Real AV storm vs worker protocol bug? |
| `crashRate` > ~25% | Oracle too broad? Harness throwing on reject? Dictionary dominating? |
| `coldStarts` ≈ `cases` with `persistent: true` | Bug — expected warm path broken |
| `resets == 0` with persistent managed | Unintended persistent state — enable `harnessStrict` |
| Persistent much “faster” than cold | Expected; validate **same crashes** on cold baseline before trusting |

Compare a short **cold** run (`persistent: false`) against a **warm** run on the same seeds when results look too good or too quiet.

---

## 9. Question results

Before celebrating or closing a campaign:

1. **Could the harness filter have blocked the path?** Grep for early `return 0` / length checks.  
2. **Could state leak explain the crash?** Re-run the crashing input under `persistent: false`.  
3. **Is the oracle honest?** Reject → `return 0`; fault → throw / AV.  
4. **Is abstraction right?** Are you fuzzing the real `parse`, or a harness-shaped toy?  
5. **Do perf numbers make sense?** Slow cases logged as warnings; investigate, don’t mute.

---

## Meaningful iterations

An iteration is meaningful when:

1. Input reached the target (honest reachability).  
2. Prior case state cannot change the outcome (no side effects).  
3. Faults are visible (crash transparency).  
4. Same input would reproduce (determinism).  
5. You could explain the outcome under both warm and cold isolation.

---

## API map (managed)

| Interface | When |
|-----------|------|
| `IInProcessHarness` | Required — `FuzzOne` |
| `IInProcessHarnessLifecycle` | `Initialize` / `Shutdown` for session state |
| `IInProcessHarnessReset` | **Required for honest persistent mode** — warn, or fail with `harnessStrict` |

Return **0** for “target finished,” including reject/error returns from the API under test.  
**Throw** (or kill the native worker) for real faults you want in the crash store.

---

## Anti-patterns

```csharp
// ❌ Harness rejects — dishonest reachability
if (data.Length < 8) return 0;
if (!LooksLikeHeader(data)) return 0;
return Target.Parse(data);
```

```csharp
// ✅ Target rejects
return Target.Parse(data); // parse returns ok/err; throw only on real bug paths
```

```csharp
// ❌ Persistent side effect
static List<byte[]> History = new();
History.Add(data.ToArray());
```

```csharp
// ❌ Swallow crash
try { Target.Parse(data); } catch { return 0; }
```

---

## Related

- [IN_PROCESS.md](IN_PROCESS.md) — how to wire harnesses  
- [PERSISTENT.md](PERSISTENT.md) — persistent / forkServer flags  
- Demo: `targets/Randall.HarnessDemo` · `projects/harness-demo.yaml`
