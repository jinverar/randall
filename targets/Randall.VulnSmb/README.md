# Randall VulnSmb

Lab TCP server with **NetBIOS session (NBSS) + SMB2-shaped** framing. Not a real Windows SMB stack.

- Default port: **4455** (avoid colliding with real SMB :445)
- Expects NBSS session messages (`0x00` + 24-bit BE length) wrapping `FE 'S''M''B'` PDUs
- Commands: Negotiate / SessionSetup / TreeConnect / Create / Read / Write
- **Create** and **Write** overflow small stack buffers on long bodies — intentional lab crashes
- Replies are ASCII tokens (`SMB_NEGO_OK`, …) for `expectResponse` / sessionGraph practice

```powershell
.\scripts\build-vulnsmb.ps1
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnsmb.yaml
```

Scare Floor: load pack `smb2-lab` on a TCP project → Prefer models → Apply.

See [docs/SMB_LAB.md](../../docs/SMB_LAB.md).
