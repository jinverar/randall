# ReelDeck — file-format media player / studio (maturity lab)

**ReelDeck** is a larger lab target shaped like a tiny **MP3 player + video maker**. It parses a toy container (`.rndl`) with multiple deep code paths so Randfuzz can practice the real maturation loop:

1. **File fuzz** → easy shallow crashes  
2. Notice we **didn’t hit** MAD / VID / studio functions  
3. **Stalk** (path novelty + seeds/dict) to push deeper  
4. Capitalize deeper crashes  

Source: `targets/reeldeck/reeldeck.c` · Profile: `projects/reeldeck.yaml` · Lab library category **file** (profile-only) · Guide below.

## Container map (`.rndl`)

```text
RNDL magic
  header (version, flags, title)     ← shallow bug A (title overflow)
  catalog
    PCM  track                       ← medium bug B (length lie)
    MAD  track (mp3-like sync)       ← deep bug C (bitrate after sync+layer3)
    VID  track (I/P/B/X frames)      ← deeper bug D (X after I+P)
    META tags
  flags & STUDIO → EDIT/RENDER       ← deepest bug E (filter / export)
```

| Depth | Stage | How you get there |
|------|--------|-------------------|
| Shallow | `parse_header` | Any oversized title |
| Medium | `decode_pcm` | PCM track with lying length dword |
| Deep | `decode_mad_layer3` | MAD + `0xFFE` sync + layer bits |
| Deeper | `decode_vid_X_after_IP` | VID frames I → P → X |
| Deepest | `studio_compose` / `studio_export_*` | `flags` STUDIO + `EDIT`…`RENDER` |

## Build

**Linux / macOS**

```bash
chmod +x scripts/build-reeldeck.sh scripts/gen-reeldeck-seeds.py
scripts/build-reeldeck.sh
python3 scripts/gen-reeldeck-seeds.py
```

**Windows** (MinGW `gcc` — same as Scream helpers)

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-reeldeck.ps1
# or via umbrella: .\scripts\build-all-lab-targets.ps1
python scripts\gen-reeldeck-seeds.py
```

`ExecutableResolver` accepts either `targets/reeldeck/reeldeck` or `reeldeck.exe`, so `projects/reeldeck.yaml` works on both OSes after build.
## Maturity playbook (fuzz → stalk → deepen)

### Round 1 — crash the lobby

```bash
dotnet run --project src/Randall.Cli -- doctor -c projects/reeldeck.yaml
dotnet run --project src/Randall.Cli -- fuzz -c projects/reeldeck.yaml --profile basic --max-iterations 80
dotnet run --project src/Randall.Cli -- crashes -p reeldeck
```

Expect **shallow** title crashes quickly. Check path stalk:

```bash
cat data/corpus/reeldeck/paths.txt
```

You will likely see `parse_header` / maybe `decode_pcm`, but **not** `decode_mad_layer3`, `decode_vid_X_after_IP`, or `studio_export_timeline`.

### Round 2 — stalk what’s missing

Compare known stages vs the map above. Arm deeper seeds + dictionary (already in the project):

```bash
# Seeds that open deep doors
ls projects/seeds/reeldeck_*.rndl

dotnet run --project src/Randall.Cli -- fuzz -c projects/reeldeck.yaml --profile fuzzier --max-iterations 200
```

Watch the live log for:

```text
+N path(s) → total T […, decode_mad_sync, decode_mad_layer3, …]
```

Path novelty **keeps** those inputs in the corpus (`paths_*.bin`) and boosts energy — this is stalking without DynamoRIO.

### Round 3 — optional Magician + Joker

```yaml
# already on in projects/reeldeck.yaml
magician: { enabled: true, … }
joker: { enabled: true, chance: 0.15, … }
```

Joker runs high-entropy iterations; Magician follows up on crashes. Oracle can request army/knight when structure/integer findings fire.

### Round 4 — DynamoRIO edges (when installed)

```bash
scripts/install-dynamorio.sh
# set coverageGuided: true (already default on reeldeck)
dotnet run --project src/Randall.Cli -- fuzz -c projects/reeldeck.yaml --coverage --max-iterations 100
dotnet run --project src/Randall.Cli -- stalk bench -c projects/reeldeck.yaml --scale 0.25
```

Now **edges** + **paths** both inform the frontier.

## Path stalking (fuzzer maturity)

File runs set `REELDECK_PATHLOG` automatically. ReelDeck appends one function name per stage. Randfuzz:

- Merges hits into `data/corpus/reeldeck/paths.txt`
- Treats **novel paths** like coverage (`+N path(s)`)
- Saves interesting inputs under the `paths` label

Cooperative targets can adopt the same env var / line format to get path stalking for free.

## Related

- [STALKING.md](STALKING.md) — profiles / bench / unlimited  
- [MAGICIAN.md](MAGICIAN.md) — spells / Joker  
- [MATURITY.md](MATURITY.md) — unfinished product map (if present)  
- [CUSTOM_TARGETS.md](CUSTOM_TARGETS.md) — bring your own binary  
