# RandfuzzGdb

Linux GDB/GEF twin of **RandfuzzDbg** for scream `.core` dumps.

Host: `randall gdb walk -i <crash-guid>` · `randall scream walk -i <guid>`

```bash
randall gdb walk -i <crash-guid>
gdb -q <exe> <core>
source tools/randfuzzgdb/scripts/rf_gdb.txt
```

| Script | Purpose |
|--------|---------|
| `scripts/rf_gdb.txt` | Registers, backtrace, stack, mappings |

Boundary: dump walks + gadget citations for **authorized lab targets**. No shellcode / payloads.

See [docs/WINDBG_FUZZ_PKG.md](../../docs/WINDBG_FUZZ_PKG.md) · [docs/MITIGATION_LAB.md](../../docs/MITIGATION_LAB.md).
