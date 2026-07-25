# Randfuzz plugins (RPP)

Drop **Randfuzz Process Plugin** folders here. Each plugin needs `rpp.yaml` + an entry script. See [docs/RPP.md](../docs/RPP.md) for the wire protocol.

## Quick start

```yaml
# rpp.yaml
name: my-mutator
runtime: python    # python | node | exe
entry: mutator.py
hook: mutate       # mutate | post_receive | post_crash | observe
```

```yaml
# project YAML
plugins:
  - path: ../plugins/my-mutator
    hook: mutate
```

Randall adds `rpp:my-mutator` to the mutator pool alongside built-in strategies.

## Plugin kinds

| Hook | Kind | When it runs | Request `op` | Typical use |
|------|------|--------------|--------------|-------------|
| **mutate** | Mutator | Before each fuzz iteration send | `mutate` | Custom byte transforms, protocol-aware flips |
| **post_receive** | Observer | After target response | `post_receive` | Abort bad sessions, log auth state, classify responses |
| **post_crash** | Oracle-adjacent | After crash recorded | `post_crash` | Tag crashes (`heap`, `uaf`), enrich triage metadata |
| **observe** | Observer | Per iteration after coverage/path | `observe` | Custom novelty / fault hints on observation bus |

**Mutators** change inputs. **Observers** classify outcomes without mutating. **Oracle-adjacent** plugins (`post_crash`, `observe`) feed triage, fault signals, and Intelligence Loop hints — they do not replace YAML `oracles:` rules.

## Included examples

| Folder | Hook | Language | What it demonstrates |
|--------|------|----------|----------------------|
| [xor-silly](xor-silly/) | `mutate` | Python | XOR, `%s` insert, run-length expand |
| [ftp-response](ftp-response/) | `post_receive` | Python | Response classification, continue/abort |
| [crash-tag](crash-tag/) | `post_crash` | Python | Crash tags for cluster metadata |
| [edge-observer](edge-observer/) | `observe` | Python | Novelty + sanitizer fault hints on observation bus |

### Test a mutator standalone

```powershell
echo '{"op":"mutate","input":"QUFBQQ=="}' | python plugins/xor-silly/mutator.py
```

## Authoring guidelines

1. **One hook per plugin folder** — split mutator vs observer if you need both.
2. **Line-delimited JSON** on stdin/stdout; one request → one response.
3. **Base64** payloads in wire messages (`input`, `response`, `output`).
4. **Soft-fail** — return valid JSON even on internal errors; use `"note"` for diagnostics.
5. **No secrets in repo** — API keys belong in env vars, not `rpp.yaml`.
6. **Cross-platform** — prefer Python 3 or Node; `exe` runtime is reserved for native helpers.

## Contributing a plugin

1. Add folder under `plugins/<name>/` with `rpp.yaml` + entry script.
2. Document behavior in a one-line comment at the top of the entry script.
3. Mention the plugin in your PR (no need for a separate doc unless the protocol is non-obvious).
4. See [CONTRIBUTING.md](../CONTRIBUTING.md) for build/test expectations.

Community plugins are **not** vetted for security — review code before enabling in production fuzz targets.

## Roadmap (honest)

| Item | Status |
|------|--------|
| `mutate` / `post_receive` / `post_crash` / `observe` | ✅ Shipped |
| `observe` → mutator credit feed | 🔲 Planned |
| Plugin catalog in web UI | 🔲 Future |
