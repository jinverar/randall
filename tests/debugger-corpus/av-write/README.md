# av-write

Write to unmapped address `0xDEADBEEF` — non-null **write** AV.

## Harness

```powershell
.\targets\debugger-corpus\debugger_corpus_fault.exe av-write
```

Fuzz path: VulnDrone TCP `HELLO` with expand mutator (similar write-AV phenotype).

## Expected observation

`Write` + `Other` address class.
