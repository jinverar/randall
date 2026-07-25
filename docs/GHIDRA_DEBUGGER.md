# Ghidra debugger + TraceRMI correlation (optional)

Randfuzz maps crash **RIP/EIP** to static functions via `randall-analysis.json` and PE/ELF fallbacks ([CRASH_ANALYSIS.md](CRASH_ANALYSIS.md)). When Ghidra is open with a live target, **TraceRMI** can translate runtime addresses back to static program addresses and optionally decompile the faulting function.

This path is **optional** — fuzz, CI, and crash export work without Ghidra or a debugger attached.

---

## What Randfuzz owns vs Ghidra

| Layer | Randfuzz | Ghidra + companions |
|-------|----------|---------------------|
| Crash RIP → function + offset | `CrashStaticFunctionMapper` (static map / PE) | — |
| Live decompile at fault PC | `randall ghidra mcp crash` (soft-fail) | GhidraMCP `/decompile_function` |
| Dynamic → static address | `GhidraMcpClient.TryDebuggerDynamicToStaticAsync` | TraceRMI via Ghidra debugger server |
| Full interactive debug | — | Ghidra Debugger (dbgeng / gdb / lldb) |

Randfuzz does **not** embed TraceRMI or launch debug sessions. We document the workflow and expose a thin CLI that queries GhidraMCP when available.

---

## Prerequisites

1. **Ghidra** with target imported — `scripts/install-ghidra.ps1`
2. **GhidraMCP** HTTP server — `scripts/install-ghidra-mcp.ps1` → **Tools → GhidraMCP → Start MCP Server** (default `http://127.0.0.1:8089/`)
3. **Optional TraceRMI debugger** — Ghidra **Debugger** tool, attach/launch target, debugger proxy on `http://127.0.0.1:8099/` (bethington/ghidra-mcp exposes `debugger_dynamic_to_static` and related tools)

Environment:

| Variable | Default | Purpose |
|----------|---------|---------|
| `GHIDRA_MCP_URL` | `http://127.0.0.1:8089` | GhidraMCP HTTP base |
| `GHIDRA_MCP_PORT` | `8089` | Port when URL unset |
| `GHIDRA_DEBUGGER_URL` | `http://127.0.0.1:8099` | TraceRMI debugger proxy |
| `GHIDRA_DEBUGGER_PORT` | `8099` | Port when debugger URL unset |

---

## CLI: annotate crash RIP

From a crash triage line or WinDbg `rip=` field:

```bash
# Static map only (no Ghidra GUI required if randall-analysis.json exists)
randall ghidra mcp crash --rip 0x401234 -p vulnserver

# Same via debugger alias
randall ghidra debugger annotate --rip 0x401234 -p vulnserver
```

**Output (when online):**

- Static function + offset from `randall-analysis.json` or PE fallback
- Optional decompiled snippet (GhidraMCP)
- Optional TraceRMI static address translation (debugger server)
- Soft-fail exit code 1 when no context available (offline MCP, no static map)

Typical workflow:

```text
fuzz crash → Investigation RIP line
      ↓
randall ghidra mcp crash --rip <pc> -p <project>
      ↓
open Ghidra → Debugger → goTo static address → set breakpoint / replay
```

---

## TraceRMI workflow (manual, in Ghidra)

1. Import/open the same binary used for fuzzing.
2. **Debugger → Configure** → select launcher (dbgeng on Windows PE, gdb/lldb on ELF).
3. Launch or attach to the target (or replay under debugger after reproducing the crash input).
4. When stopped at the fault, note the **dynamic** PC.
5. Use Ghidra's **dynamic → static** mapping (TraceRMI) or Randfuzz CLI above.
6. Cross-check with stalk layers / crash pack bookmarks from `randall export -i <guid>`.

Randfuzz crash packs already include `ghidra_import.py` focus bookmarks; debugger correlation adds **live** address translation when ASLR/rebase differs from the static map.

---

## Honest limits (Phase 5)

| Capability | Status |
|------------|--------|
| Static RIP → function (JSON map) | ✅ Real |
| CLI `ghidra mcp crash` | ✅ Real (soft-fail offline) |
| GhidraMCP decompile snippet | ✅ Real when MCP online |
| TraceRMI dynamic→static via HTTP | ✅ Stub — tries debugger endpoints; requires Ghidra debugger session |
| Auto-launch debugger from Randfuzz | 🔲 Not planned — manual Ghidra UX |
| Observation bus publish on annotate | 🔲 Future |

See also: [GHIDRA_INTEGRATION.md](GHIDRA_INTEGRATION.md) · [CRASH_ANALYSIS.md](CRASH_ANALYSIS.md)
