# oob-write

Out-of-bounds heap write — managed fixture until native overrun harness lands.

- stub: True
- harness: `debugger_corpus_fault.exe oob-write`
- CI: managed ParseBlocks fixture asserts normalized fields; live cdb soft-skips without WinDbg.
