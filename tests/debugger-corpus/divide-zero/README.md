# divide-zero

Native integer division by zero — exception `0xC0000094` (not an access violation).

## Harness

```powershell
.\targets\debugger-corpus\debugger_corpus_fault.exe divide-zero
```

## Expected observation

Exception code `c0000094`; access/address class remain `Unknown`.
