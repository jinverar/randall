# Persistent mode & fork server

AFL-style speedups: **don’t pay process-start cost every test case**.

Persistent mode only works if the harness follows [HARNESS_DESIGN.md](HARNESS_DESIGN.md):  
**no persistent side effects**, honest **`Reset()`**, crash transparency. Warm process ≠ warm case state.

| Flag | Meaning in Randfuzz |
|------|---------------------|
| `fuzz.persistent` | Keep harness/target warm across cases. **null** → true for in-process, **false** for OOP |
| `fuzz.forkServer` | Warm worker + recycle after crash. **null** → follow `persistent` (in-process). Windows ≠ Unix `fork` |
| `fuzz.harnessStrict` | Fail start if persistent managed harness lacks `IInProcessHarnessReset` |

Full isolation matrix (persistent × forkServer × cold): [HARNESS_DESIGN.md](HARNESS_DESIGN.md#isolation-matrix-what-randfuzz-actually-does).

---

## In-process

```yaml
kind: harness
target:
  harness: ../path/MyHarness.dll
  harnessType: managed   # or native
fuzz:
  executionMode: in-process
  persistent: true
  forkServer: true
  harnessStrict: true
```

| Mode | Config | Behavior |
|------|--------|----------|
| Warm + recycle | `persistent: true`, `forkServer: true` | Reset each case; reload/respawn after crash |
| Warm only | `persistent: true`, `forkServer: false` | Reset each case; managed stays loaded after exception |
| Cold (non-persistent) | `persistent: false` | Reload / new worker **every** case — reproducibility baseline |

Demo: `projects/harness-demo.yaml`

---

## Out-of-process persistent stdio

Opt-in (defaults off):

```yaml
kind: stdio   # or file (stdin protocol, not {file} args)
target:
  executable: ../targets/my_persistent_harness.exe
fuzz:
  executionMode: out-of-process
  persistent: true
  forkServer: true
```

**Protocol** (little-endian):

```
→ u32 length | raw bytes
← "OK\n"  or  "CRASH …\n"  or process exit
```

Environment: `RANDALL_PERSISTENT=1`, and `RANDALL_FORK_SERVER=1` when `forkServer` is on.

Without these flags, Randfuzz uses normal per-case spawn (non-persistent OOP).

---

## Windows vs Linux

| Platform | `forkServer` behavior |
|----------|------------------------|
| **Windows** | Warm persistent process (no `fork`). Same idea as winAFL persistent mode, not AFL `FORKSRV_FD`. |
| **Linux** | Prefer classic AFL `FORKSRV_FD` (198/199) when the target handshakes; otherwise warm stdio. |

### Linux AFL FORKSRV_FD

When `forkServer: true` on Linux, Randfuzz tries an AFL classic forkserver via the native
helper `randall_forksrv_helper` (CLR never forks). The target must:

1. Write a 4-byte hello to fd **199**
2. Loop: read 4 bytes from fd **198**, `fork()`, write child pid to **199**, `waitpid`, write status to **199**
3. Child consumes `{file}` / `@@` input (helper rewrites the file each case)

Demo:

```bash
gcc -O0 -g -o targets/forksrv-demo/forksrv_demo targets/forksrv-demo/forksrv_demo.c
gcc -O2 -o targets/forksrv-demo/randall_forksrv_helper targets/forksrv-demo/randall_forksrv_helper.c
dotnet run --project src/Randall.Cli -- fuzz -c projects/forksrv-demo.yaml
# Expect mode afl-forksrv and crashes when mutators insert '!'
```

Targets that do not speak FORKSRV (or missing helper) fall back to warm stdio automatically.

For network services (`kind: tcp` + `longLived`), Target Runtime already keeps the server warm. Use `persistent`/`forkServer` for **harness / stdio / file** targets.

---

## Related

- [HARNESS_DESIGN.md](HARNESS_DESIGN.md) — principles, anti-goals, perf signals  
- [IN_PROCESS.md](IN_PROCESS.md) — in-process vs out-of-process  
- [TARGET_RUNTIME.md](TARGET_RUNTIME.md) — long-lived TCP/UDP processes  
