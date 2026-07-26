# null-deref

Deterministic **write** to address `0` — classic null-pointer dereference.

## Harness

```powershell
.\targets\debugger-corpus\debugger_corpus_fault.exe null-deref
```

Alternate: `targets/screamcrash/scream_crash.exe` (Scream selftest — same fault class).

## Expected observation

See `expected.json`: `Write` + `NullPage` + `ACCESS_VIOLATION`.
