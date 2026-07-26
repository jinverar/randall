# stack-corrupt

Stack corruption / smash — managed fixture (Stackish address class).

- stub: True
- harness: `debugger_corpus_fault.exe stack-corrupt`
- CI: managed ParseBlocks fixture asserts normalized fields; live cdb soft-skips without WinDbg.
