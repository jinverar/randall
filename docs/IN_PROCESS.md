# In-process vs out-of-process fuzzing

Randfuzz supports **both**. Pick per project in YAML.

**Before writing a harness:** read [HARNESS_DESIGN.md](HARNESS_DESIGN.md) — minimalism, honest reachability, *let the target reject invalid input*, reset/cleanup.

| Mode | Best for | How it runs |
|------|----------|-------------|
| **out-of-process** (default) | Network services, full apps, remote agent, dumps + memory lens | Separate OS process — Target Runtime / TCP / file spawn |
| **in-process** | Parsers, libraries, libFuzzer-style harnesses | Bytes fed into a harness DLL inside a worker (or managed host) |

---

## Out-of-process (default)

```yaml
kind: tcp
target:
  executable: ../targets/myapp/myapp.exe
  longLived: true
fuzz:
  executionMode: out-of-process   # optional — this is the default
```

Use this for the stalk loop, remote lab, minidumps, and memory lens.

---

## In-process

```yaml
name: harness-demo
kind: harness
target:
  harness: ../targets/Randall.HarnessDemo/bin/Debug/net8.0/Randall.HarnessDemo.dll
  harnessType: managed          # auto | managed | native
fuzz:
  executionMode: in-process
  persistent: true       # false = cold reload every case
  forkServer: true
  harnessStrict: true    # require IInProcessHarnessReset when persistent
  maxIterations: 200
```

Defaults: in-process is **persistent** unless you set `persistent: false`. See isolation matrix in [HARNESS_DESIGN.md](HARNESS_DESIGN.md).

### Managed harness (.NET)

1. Create a class library referencing `Randall.Contracts`.
2. Implement `IInProcessHarness` (optional `IInProcessHarnessLifecycle`).
3. Point `target.harness` at the built DLL.

```csharp
public sealed class MyParser : IInProcessHarnessLifecycle, IInProcessHarnessReset
{
    public void Initialize() { /* session state once */ }
    public void Shutdown() { }
    public void Reset() { /* clear per-case state every iteration */ }

    public int FuzzOne(ReadOnlySpan<byte> data)
    {
        // Call the target — do not filter. return 0 even when target rejects.
        // Throw (or let native AV kill the worker) for real faults.
        Target.Parse(data);
        return 0;
    }
}
```

Managed exceptions are caught and saved as crashes **without** being swallowed (`return 0`). Missing `IInProcessHarnessReset` warns in persistent mode, or **fails start** when `harnessStrict: true`. Session end prints harness perf (`avgFuzzOne`, resets, recycles) — question outliers.

### Native harness (C/C++ / libFuzzer ABI)

Export (cdecl):

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
```

```yaml
target:
  harness: ../targets/mylib/fuzz.dll
  harnessType: native
  harnessExport: LLVMFuzzerTestOneInput   # default
fuzz:
  executionMode: in-process
```

Native code runs in an **isolated worker** (`randall harness-worker`) so an AV kills only the worker; Randfuzz restarts it and records the crash.

---

## Demo

```powershell
dotnet build targets/Randall.HarnessDemo
dotnet run --project src/Randall.Cli -- fuzz -c projects/harness-demo.yaml
```

Dictionary includes `CRASH` — when a mutant starts with those bytes the demo harness throws and you get a saved crash.

---

## Choosing

| Goal | Mode |
|------|------|
| Vulnserver / custom TCP app / remote VM | out-of-process |
| Fast parser / codec / library | in-process |
| Need minidumps + memory lens on a real EXE | out-of-process |
| libFuzzer-compatible DLL | in-process + native |

You can keep **two project YAMLs** for the same research target (one OOP service, one in-process unit harness).

**Speed:** add `fuzz.persistent: true` and `fuzz.forkServer: true` — see [PERSISTENT.md](PERSISTENT.md).
