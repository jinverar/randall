# Release packaging cadence

Randfuzz ships as a **portable folder**, not a signed installer (yet).

## What “pack” produces

```bash
# Host RID by default (win-x64 / linux-x64 / osx-*)
dotnet run --project src/Randall.Cli -- pack -o publish/standalone

# Explicit RID
dotnet run --project src/Randall.Cli -- pack -o publish/standalone-win --rid win-x64
dotnet run --project src/Randall.Cli -- pack -o publish/standalone-linux --rid linux-x64
```

Wrappers:

- Windows: `scripts/publish-standalone.ps1`
- Linux/macOS: `scripts/publish-standalone.sh`

Contents: self-contained `cli/` + `server/`, copied `projects/` / `docs/` / `campaigns/`, empty `data/` + `targets/`, and `start.cmd` or `start.sh`.

**Not included:** DynamoRIO, AFL++, MinGW, or prebuilt lab `.exe`s — build those on the lab box (`build-all-lab-targets.ps1` / `build-lab-targets.sh` + `build-file-text.sh` / `build-reeldeck.sh`).

## Suggested GitHub Release checklist

1. Tag `v0.x.y` from `main` after CI green (`dotnet test` + smoke).
2. Attach packs for at least **win-x64** and **linux-x64** (zip the `publish/standalone*` folders).
3. Release notes link: [INSTALL_WINDOWS.md](INSTALL_WINDOWS.md), [INSTALL_LINUX.md](INSTALL_LINUX.md), [BENCHMARKS.md](BENCHMARKS.md), [MATURITY.md](MATURITY.md).
4. Call out: portable packs are verified at update-time via signed `update-manifest.json` (see [UPDATES.md](UPDATES.md)); Authenticode on the `.exe` itself is still unfinished.
5. Attach `update-manifest.json` + `update-manifest.json.sig` + RID zips.

## Still unfinished (maturity)

- Authenticode / Linux package signing of the binaries themselves
- Single zip that bundles lab targets + tools
- Auto-publish workflow

Until then, keep README honest: **portable pack**, not “installer.” Updates: [UPDATES.md](UPDATES.md).
