# file-framed mini-parser

In-repo length-prefixed binary teaching target for `projects/file-framed.yaml`.

```bash
scripts/build-file-framed.sh
dotnet run --project src/Randall.Cli -- fuzz -c projects/file-framed.yaml
```

Accepts `FRM0` frames or bare `u32le` length + payload + checksum (protocol model).
Bugs: length lies, `BOOM`/`DEAD` payloads, `DEEP` deep path.
