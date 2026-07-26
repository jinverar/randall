# heap-overflow (stub)

**TODO** — intentional one-past-end heap write with PageHeap-friendly layout.

Current harness argv `heap-overflow` exits with code 2. Expected sidecar documents target phenotype only; live cdb integration tests skip stubs.

## Planned harness

Small `malloc` + `strcpy` one byte past allocation; run under PageHeap for clearer `!heap` signal.
