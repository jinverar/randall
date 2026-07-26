# av-read

Read from an unmapped user address (`0xDEADBEEF`) — **read** access violation.

## Harness

```powershell
.\targets\debugger-corpus\debugger_corpus_fault.exe av-read
```

## Expected observation

`Read` access, non-null `Other` address class, `c0000005`.
