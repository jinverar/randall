# SMB lab path (Phase 22)

Randfuzz’s SMB support is **lab-first**: NetBIOS session framing + SMB2-shaped headers/commands against intentionally weak services — not production Windows SMB + signing + Kerberos.

## What you get

| Piece | Location |
|-------|----------|
| NBSS + SMB2 models | `projects/protocols/smb2_*.yaml` |
| Scare Floor pack | `projects/protocols/packs/smb2-lab/` |
| Crashable lab server | `targets/Randall.VulnSmb` → port **4455** |
| Campaign profile | `projects/vulnsmb.yaml` |

## Quick path (VM)

```powershell
.\scripts\build-vulnsmb.ps1
# Scare Floor: TCP project vulnsmb → Load pack smb2-lab → Prefer models → Apply
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnsmb.yaml
```

Point `transport.host` at a lab VM listener. Prefer **:4455** (or another non-production port). Do **not** default-scan corporate :445.

## Session shape

1. **NEGOTIATE** → `SMB_NEGO_OK`
2. **SESSION_SETUP** (null/guest lab — no Kerberos) → `SMB_SESS_OK`
3. **TREE_CONNECT** → `SMB_TREE_OK`
4. **CREATE** (mutable name/body — VulnSmb stack overflow when long) → `SMB_CREATE_OK`
5. Optional **WRITE** / **READ**

`sessionGraph` edges follow those ASCII status tokens (same pattern as VulnRpc).

## Named pipe → DCERPC

Pack **`smb-pipe-dce`**: Negotiate → SessionSetup → TreeConnect (`IPC$`) → Create (`\pipe\randall`) → Write(DCE bind) → Write(DCE request).

On VulnSmb, SMB2 **Write** bodies that start with DCE (`05 00 …`) are handled like VulnRpc:

| DCE ptype | Reply |
|-----------|--------|
| bind (11) | `BIND_ACK` |
| request (0), opnum 2 | overflow stub + `RPC_OK` |

Scare Floor: load pack `smb-pipe-dce`, or build a layered PDU with **Stack: NBSS/SMB2/DCE** (`len-prefix` format `nbss`).

## Honest limits

- No SMB signing, encryption, or modern auth
- Replies are lab ASCII tokens, not full SMB2 response PDUs
- Dialects / credit / async I/O are stubbed
- Production SMB fuzzing is a research product of its own — this phase targets **lab parsers / legacy / intentionally weak services**
