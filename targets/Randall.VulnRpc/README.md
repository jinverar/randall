# Randall VulnRpc

Lab TCP server with **DCE/RPC-shaped** bind + request framing. Not a real Windows RPC / NDR stack.

- Default port: **1355**
- Accepts connection-oriented DCE header (`rpc_vers=5`, `frag_length`, `call_id`, …)
- **Bind** (`ptype=11`) → ASCII `BIND_ACK`
- **Request** (`ptype=0`):
  - `opnum=1` → `RPC_OK` (safe)
  - `opnum=2` → copies stub into a 64-byte stack buffer (**intentional overflow**)

```powershell
.\scripts\build-vulnrpc.ps1
.\targets\vulnrpc\randall-vulnrpc.exe
# or via project:
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnrpc.yaml
```

Scare Floor: load pack `dce-bind-request` on a TCP project → Prefer models → Apply.
