# uaf (stub)

**TODO** — use-after-free with freed-heap probe visible in cdb `!address`.

Harness argv `uaf` currently exits 2. Expected fields document the target `Freed` address class once implemented.

## Planned harness

`malloc(64)` → `free` → read through dangling pointer; PageHeap recommended for triage.
