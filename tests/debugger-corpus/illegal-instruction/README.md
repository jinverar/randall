# illegal-instruction

Raises `STATUS_ILLEGAL_INSTRUCTION` (`0xC000001D`) — exercises non-AV exception parsing.

## Harness

```powershell
.\targets\debugger-corpus\debugger_corpus_fault.exe illegal-instruction
```

## Expected observation

Exception hint contains `ILLEGAL`; no AV access/address classification.
