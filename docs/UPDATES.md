# Secure updates

Randfuzz can **check** for updates over HTTPS and **apply** them only when you confirm. Major updates raise an in-UI banner (and optional Discord ping). Apply always requires an explicit action — nothing silent-patches the lab box.

## Security model

| Control | Behavior |
|---------|----------|
| Transport | HTTPS only; downloads allowlisted to GitHub hosts; no URL credentials |
| Authenticity | ECDSA P-256 signature over `update-manifest.json` |
| Integrity | Per-asset SHA-256 (+ size when provided) in the signed manifest |
| Zip safety | Zip-slip blocked; path traversal rejected; uncompressed size capped |
| Source apply | `origin` must match `github.com/<owner>/<repo>`; `merge --ff-only` only |
| Consent | `randall update apply --yes` or UI **Update now** (confirm dialog) |
| Locking | Single apply at a time via `data/updates/.apply.lock` |
| Caching | Successful checks reuse for 1 hour unless `--force` |
| Major notify | Banner only when signature-valid; Discord webhook host-allowlisted |

Unsigned GitHub tags/zips are **not** applied. Check may still report “no signed manifest” until a release publishes both:

- `update-manifest.json`
- `update-manifest.json.sig`

Public verify key is embedded (`UpdateCrypto.EmbeddedPublicKeyPem`). Override for labs/tests with `RANDALL_UPDATE_PUBKEY_PEM`.

Fail-closed: bad signature, product/channel/severity mismatch, unsafe asset names, or oversized payloads → no update offered.

## User commands

```bash
randall update check [--force]   # query latest signed release (cached ~1h)
randall update status            # last check / dismiss state
randall update apply --yes       # download+verify+apply when you are ready
randall update dismiss           # hide major banner for the pending version
```

UI: sticky banner on **signature-valid major** updates → **Notes** (https://github.com only) / **Update now** / **Dismiss**.

### Install modes

| Mode | Detection | Apply |
|------|-----------|-------|
| **Source** | `Randall.sln` present | Verify trusted `origin` → `git fetch --tags` → `merge --ff-only` → `dotnet build -c Release` |
| **Portable** | `cli/` + `server/` pack | Download RID zip → size/SHA-256 → safe extract → finish script swaps `cli/`/`server/` (preserves `data/`, `targets/`, `projects/local/`) |

## Releaser checklist

1. Pack: `randall pack -o publish/standalone-linux --rid linux-x64` (writes `update-manifest.DRAFT.json`).
2. Zip the folder → `randfuzz-linux-x64.zip` (and win-x64 counterpart).
3. Fill SHA-256 + size into `update-manifest.json` (rename from DRAFT; set `severity: major` when the release should force the banner). Keep `releaseTag` aligned with `version`.
4. Sign:

```bash
export RANDALL_UPDATE_SIGNING_KEY_PEM=/path/to/private.pem
randall update sign-manifest -i update-manifest.json -k "$RANDALL_UPDATE_SIGNING_KEY_PEM"
```

5. GitHub Release `vX.Y.Z` — attach zips + `update-manifest.json` + `update-manifest.json.sig`.

Env overrides:

- `RANDALL_UPDATE_REPO=owner/repo` (default `jinverar/randall`; tokens must be safe `[A-Za-z0-9._-]`)
- `RANDALL_UPDATE_MANIFEST_URL=https://…/update-manifest.json` (tests / mirrors; `.sig` fetched as sibling; still signature-verified)

## Signing key

The verify public key ships in-repo. The matching **private** signing key must live in your secrets store — never commit it. Rotate if unsure.

```bash
openssl ecparam -name prime256v1 -genkey -noout -out update-signing-key.pem
openssl ec -in update-signing-key.pem -pubout -out update-pubkey.pem
# Replace UpdateCrypto.EmbeddedPublicKeyPem with update-pubkey.pem contents, then ship a release.
```
