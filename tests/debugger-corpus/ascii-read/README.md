# ascii-read

Read ACCESS_VIOLATION at ASCII-controlled address 0x41414141.

- stub: False
- harness: `debugger_corpus_fault.exe ascii-read`
- CI: managed ParseBlocks fixture asserts normalized fields; live cdb soft-skips without WinDbg.
