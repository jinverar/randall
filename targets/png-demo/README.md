# png-demo — competitive PNG file-fuzz target

Tiny **real PNG chunk walker** (signature + length/type/CRC layout per ISO 15948)
with **intentional lab vulns** — not an upstream CVE hunt and not a full zlib/IDAT decoder.

| Mode | Artifact | Profile |
|------|----------|---------|
| Cold OOP `{file}` | `png-demo.exe` / `app.exe` | `projects/png-demo.yaml` |
| In-process native | `png-demo.dll` / `.so` (`LLVMFuzzerTestOneInput`) | `projects/png-demo-harness.yaml` |

## Bugs (abort)

| Id | Trigger |
|----|---------|
| A | Chunk length past EOF |
| B | IHDR `width * height` product overflow |
| C | Chunk type `FUZZ` + payload starting `BOOM` |

Soft reject (exit **1**, not a crash): bad signature / truncated file.

## Build

```powershell
.\scripts\build-png-demo.ps1
```

```bash
scripts/build-png-demo.sh
```

## Fuzz

```powershell
dotnet run --project src/Randall.Cli -- fuzz -c projects/png-demo.yaml
dotnet run --project src/Randall.Cli -- fuzz -c projects/png-demo-harness.yaml
```

Full competitive walkthrough: [docs/FILE_FUZZING.md](../../docs/FILE_FUZZING.md) § Competitive demo: png-demo.
