# integer-trunc

Integer truncation / size mismatch leading to bounded write fault — fixture.

- stub: True
- harness: `debugger_corpus_fault.exe integer-trunc`
- CI: managed ParseBlocks fixture asserts normalized fields; live cdb soft-skips without WinDbg.
