# Secure updates

Randfuzz can **check** for updates over HTTPS and **apply** them only when you confirm. Major updates raise an in-UI banner (and optional Discord ping). Apply always requires an explicit action — nothing silent-patches the lab box.

## Security model

| Control | Behavior |
|---------|----------|
| Transport | HTTPS only; downloads allowlisted to GitHub hosts |
| Authenticity | ECDSA P-256 signature over `update-manifest.json` |
| Integrity | Per-asset SHA-256 in the signed manifest |
| Consent | `randall update apply --yes` or UI **Update now** (confirm dialog) |
| Major notify | Banner + optional `RANDALL_DISCORD_WEBHOOK` (once per version) |

Unsigned GitHub tags/zips are **not** applied. Check may still report “no signed manifest” until a release publishes both:

- `update-manifest.json`
- `update-manifest.json.sig`

Public verify key is embedded in the binary (`UpdateCrypto.EmbeddedPublicKeyPem`). Override for labs/tests with `RANDALL_UPDATE_PUBKEY_PEM`.

## User commands

```bash
randall update check          # query latest signed release
randall update status         # last check / dismiss state
randall update apply --yes    # download+verify+apply when you are ready
randall update dismiss        # hide major banner for the pending version
```

UI: sticky banner on major updates → **Notes** / **Update now** / **Dismiss**.

### Install modes

| Mode | Detection | Apply |
|------|-----------|-------|
| **Source** | `Randall.sln` present | `git fetch --tags` + `merge --ff-only` to release tag + `dotnet build -c Release` |
| **Portable** | `cli/` + `server/` pack | Download RID zip → SHA-256 → stage → finish script swaps `cli/`/`server/` (preserves `data/` + `targets/`) |

## Releaser checklist

1. Pack: `randall pack -o publish/standalone-linux --rid linux-x64` (writes `update-manifest.DRAFT.json`).
2. Zip the folder → `randfuzz-linux-x64.zip` (and win-x64 counterpart).
3. Fill SHA-256 + size into `update-manifest.json` (rename from DRAFT; set `severity: major` when the release should force the banner).
4. Sign:

```bash
export RANDALL_UPDATE_SIGNING_KEY_PEM=/path/to/private.pem
randall update sign-manifest -i update-manifest.json -k "$RANDALL_UPDATE_SIGNING_KEY_PEM"
```

5. GitHub Release `vX.Y.Z` — attach zips + `update-manifest.json` + `update-manifest.json.sig`.

Env overrides:

- `RANDALL_UPDATE_REPO=owner/repo` (default `jinverar/randall`)
- `RANDALL_UPDATE_MANIFEST_URL=https://…/update-manifest.json` (tests / mirrors; `.sig` fetched as sibling)

## Signing key

The verify public key ships in-repo. The matching **private** signing key must live in your secrets store — never commit it. A copy from the key-generation session may be available as a cloud-agent artifact for the repo owner; rotate if unsure.

Generate a replacement pair:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out update-signing-key.pem
openssl ec -in update-signing-key.pem -pubout -out update-pubkey.pem
# Replace UpdateCrypto.EmbeddedPublicKeyPem with update-pubkey.pem contents, then ship a release.
```
