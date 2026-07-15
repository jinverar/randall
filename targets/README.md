# Lab targets

Copy binaries here before fuzzing. Randall project YAMLs reference these paths.

## vulnserver

1. Download [Vulnserver](https://github.com/stephenbradshaw/vulnserver) or use your existing lab copy.
2. Place `vulnserver.exe` at:

   ```
   targets/vulnserver/vulnserver.exe
   ```

3. Fuzz:

   ```powershell
   dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnserver.yaml
   ```

   Randall starts vulnserver, sends mutated payloads to `127.0.0.1:9999`, detects when the process dies.

## Generic file templates

`projects/file-text.yaml` and `projects/file-framed.yaml` are **placeholders**. Edit `target.executable`, seeds, and block models for your format.

## Private targets (not committed)

Keep real lab binaries and configs out of the public repo:

```
targets/local/          ← your executables
projects/local/         ← your YAML + seeds (gitignored)
```

```powershell
dotnet run --project src/Randall.Cli -- fuzz -c projects/local/my-target.yaml
```

## Crashes

Saved under `data/crashes/<target>/` with `index.jsonl` metadata.

```powershell
dotnet run --project src/Randall.Cli -- crashes
dotnet run --project src/Randall.Cli -- crashes -p vulnserver
```
