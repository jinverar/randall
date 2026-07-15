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

   Randall starts vulnserver, sends `TRUN /.:/` + mutated bytes to `127.0.0.1:9999`, detects when the process dies.

## Notepad++

Uses default install path in `projects/notepadpp.yaml`. Edit `target.executable` if yours differs.

```powershell
dotnet run --project src/Randall.Cli -- fuzz -c projects/notepadpp.yaml
```

Fuzzes `.xml` and `.txt` seeds — tricky mutations on structure and boundaries.

## cfpass

Your lab binary for **strange / proprietary file formats**.

1. Copy `cfpass.exe` to `targets/cfpass/cfpass.exe`
2. Replace seeds in `projects/seeds/` with a **valid** sample from your format (keep magic bytes / structure)
3. Edit `projects/cfpass.yaml` — especially `target.args` if the app uses `open`, `-f`, or GUI-only load

```powershell
dotnet run --project src/Randall.Cli -- fuzz -c projects/cfpass.yaml
```

## Crashes

Saved under `data/crashes/<target>/` with `index.jsonl` metadata.

```powershell
dotnet run --project src/Randall.Cli -- crashes
dotnet run --project src/Randall.Cli -- crashes -p vulnserver
```
