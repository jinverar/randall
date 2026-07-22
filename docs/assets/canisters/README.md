# Scream canister art

Industrial-horror harvest canisters for the Crashes tab (*Scare it. Bottle the scream.*).

| File | Use |
|------|-----|
| `canister-empty.jpg` | laughter — 0 unique screams |
| `canister-low.jpg` | watching — 1–2 unique (yelps) |
| `canister-mid.jpg` | toxic — 3–7 unique, or any critical |
| `canister-full.jpg` | virulent — ≥8 unique, or ≥3 critical |
| `canister-eip.jpg` | EIP/RIP overwrite seal (wins over all moods) |
| `canister-rack.jpg` | Crashes header atmosphere |

Served by Randall.Server as `/canisters/canister-*.jpg` (same `ServeRepoAsset` pattern as `/randall.png`).

UI copies also under `src/Randall.Server/wwwroot/img/canisters/`. Lore: [LORE.md](../LORE.md).

## UI behavior

Porthole fill is progressive (count toward capacity) with a mood floor so empty/laughter stays dry and EIP always reads full. An analog gauge needle tracks the same fill. Continuous fill/vapor/pulse animations stay **off by default**.

## UI-only (no fuzz RAM)

These JPEGs are served to the browser. They are **not** loaded by `randall fuzz` / DynamoRIO.
Leaving the Crashes tab open costs a few hundred KB of browser image decode at most — irrelevant
next to coverage instrumentation.

**Defaults:** canister rack **on**; fill/vapor/pulse **animations off**. The special
moment is **EIP/RIP control** (dedicated art + badge + EIP CAPTURED), not fill percentage.

Original factory art for Randfuzz parody — not Disney/Pixar product likenesses.
