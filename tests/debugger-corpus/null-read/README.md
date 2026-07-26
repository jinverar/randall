# null-read

Read ACCESS_VIOLATION at address 0 (null page).

- stub: False
- harness: `debugger_corpus_fault.exe null-read`
- CI: managed ParseBlocks fixture asserts normalized fields; live cdb soft-skips without WinDbg.
