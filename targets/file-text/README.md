# file-text mini-parser

In-repo structured text / XML teaching target for `projects/file-text.yaml`.

```bash
scripts/build-file-text.sh          # Linux
# scripts/build-file-text.ps1       # Windows (MinGW gcc)
dotnet run --project src/Randall.Cli -- fuzz -c projects/file-text.yaml
```

Bugs: oversized element names, `<BOOM>` tag, lying `len="N"` attributes.
