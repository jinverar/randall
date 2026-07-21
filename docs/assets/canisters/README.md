# Scream canister art

Industrial-horror harvest canisters for the Crashes tab (*Scare it. Bottle the scream.*).

| File | Use |
|------|-----|
| `canister-empty.jpg` | 0% fill |
| `canister-low.jpg` | ~1–33% |
| `canister-mid.jpg` | ~34–66% |
| `canister-full.jpg` | ~67%+ / pressure critical |
| `canister-rack.jpg` | Crashes header atmosphere |

Served by Randall.Server as `/canisters/canister-*.jpg` (same `ServeRepoAsset` pattern as `/randall.png`).

UI copies also under `src/Randall.Server/wwwroot/img/canisters/`. Lore: [LORE.md](../LORE.md).

## UI-only (no fuzz RAM)

These JPEGs are served to the browser. They are **not** loaded by `randall fuzz` / DynamoRIO.
Leaving the Crashes tab open costs a few hundred KB of browser image decode at most — irrelevant
next to coverage instrumentation.

**Defaults:** canister rack **on**; fill/vapor/pulse **animations off** (toggle on the Crashes
harvest panel). Instant fill updates still work without animations.

Original factory art for Randfuzz parody — not Disney/Pixar product likenesses.
