# Fuzzing RPC with a known stub layout (Phase 21)

Randfuzz does **not** ship a full Windows RPC / Impacket-class NDR stack. Phase 21 is **lab-first**: DCE-shaped framing + a known stub layout you control.

## What you get

| Piece | Location |
|-------|----------|
| Bind / request models | `projects/protocols/dce_bind.yaml`, `dce_request.yaml` |
| Scare Floor pack | `projects/protocols/packs/dce-bind-request/` |
| Crashable lab server | `targets/Randall.VulnRpc` → port **1355** |
| Campaign profile | `projects/vulnrpc.yaml` |

## Quick path (VM)

```powershell
.\scripts\build-vulnrpc.ps1
# Scare Floor: TCP project vulnrpc → Load pack dce-bind-request → Prefer models → Apply
# or:
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnrpc.yaml
```

Session: **BIND** (`ptype=11`) → expect `BIND_ACK` → **REQUEST** (`ptype=0`, `opnum=2`) with a mutable stub. VulnRpc overflows a 64-byte stack buffer on opnum 2 when the stub is long.

## Honest limits vs Impacket / Windows RPC

- No full MIDL/NDR marshaling, no auth (NTLM/Kerberos), no complex pointers / conformance.
- You supply the stub layout (hex / sized fields / **minimal IDL**) for **your** lab interface.
- Replies from VulnRpc are ASCII lab tokens (`BIND_ACK`, `RPC_OK`), not real `bind_ack` PDUs — enough for `expectResponse` / sessionGraph practice.
- Named-pipe → DCERPC under SMB is Phase 22 (`p22-pipe`) — see [SMB_LAB.md](SMB_LAB.md).

## Minimal IDL → stub model

```powershell
randall case idl -p vulnrpc --name op2_stub --file examples/idl/op2_stub.idl
```

Scare Floor: **IDL → stub model** (paste a `typedef struct { … } Name;`). Supports `uint16`/`uint32`/`uint64`, `byte[n]`, `wchar_t[n]` (as UTF-16LE bytes), and best-effort `uint32 len; byte data[len];` → `sized`.

Wire the resulting `protocols/op2_stub.yaml` into a REQUEST model or replace the opaque stub `bytes` block.

## Custom stub

1. Scare Floor → edit REQUEST stub blocks, **Import IDL**, or Promote PDU → model.
2. Set `opnum` / `alloc_hint` / `frag_length` to match your layout (keep frag_length coherent or let mutators explore broken lengths).
3. Point `transport.host` at your VM service — never scan production RPC endpoints by default.
