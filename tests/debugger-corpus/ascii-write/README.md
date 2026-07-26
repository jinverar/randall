# ascii-write

Write through pointer `0x41414141` — Scream Investigator should classify **AsciiPattern** and HIGH input influence.

## Harness

```powershell
.\targets\debugger-corpus\debugger_corpus_fault.exe ascii-write
```

Alternate: TCP `randall-screamcrash` + line containing `SCREAM` → `scream_av.dll`.

## Expected observation

`Write` + `AsciiPattern` + `HIGH` input influence.
