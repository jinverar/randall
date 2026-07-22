# Web application fuzzing

Randfuzz fuzzes web apps as **`kind: http`** (or `https`) — same TCP tube path as protocol labs, plus HTTP helpers (Content-Length sync, HTTP status class in oracles).

This is not GUI stalking. Point `transport.host` / `port` at a local or lab web server and mutate HTTP requests.

## Quick start

```bash
# Lab target (overflows on URI / Host / Cookie / body)
# scripts/build-vulnhttp.ps1   # Windows lab binary

randall fuzz -c projects/webapp.yaml
randall oracles -p webapp
```

Demo profile: `projects/webapp.yaml`. Legacy: `projects/vulnhttp.yaml` (`kind: tcp` still works).

## Project shape

```yaml
kind: http                 # or https (enables TLS)
transport:
  type: http
  host: 127.0.0.1
  port: 8080
  # https:
  #   tls: true
  #   tlsInsecure: true
  #   tlsHost: localhost
sessionCommands:
  - name: GET
    model: protocols/http_get.yaml
    expectResponse: "HTTP/"
  - name: POST
    model: protocols/http_post.yaml
    expectResponse: "HTTP/"
fuzz:
  syncContentLength: true  # rewrite Content-Length after body mutate
  syncCookies: true        # absorb Set-Cookie → inject Cookie on later requests (minimal jar)
dictionaryFile: dictionaries/ai_codegen_mistakes.txt
oracles:
  enabled: true
```

Create a profile: `randall case new --kind http --name myweb --host 127.0.0.1 --port 8080`

## Cookie jar (v1 stub)

When `fuzz.syncCookies: true` **or** `kind: http|https`, Randfuzz keeps a per-run jar:

1. Parse `Set-Cookie` from responses (`name=value`, attributes stripped)
2. Inject / replace a `Cookie:` header on outbound HTTP requests

Not a browser: no Path/Domain/Secure/SameSite expiry, no redirect following. Good enough for lab session cookies on VulnHttp-style targets.
## What gets fuzzed

| Surface | How |
|---------|-----|
| Method / URI / Host / Cookie / User-Agent | `protocols/http_get.yaml` mutable blocks |
| POST body + Content-Length | `protocols/http_post.yaml` + `syncContentLength` |
| Injection / traversal / SSRF tokens | dictionary (Bug Hunter **Seed** channel) |
| Auth skip / wrong 200 / huge responses | Oracle engine (**Oracle** / **Hybrid** channel) |

## Bug Hunter channels (web)

| Class | Channel | Web action |
|-------|---------|------------|
| `auth-skip`, `error-swallow`, `resource` | Oracle | judge responses |
| `inject-sqli`, `inject-cmd`, `ssrf`, `mem-classic` | Seed | dictionary / seeds |
| `inject-xss`, `path-inject`, `length-lie` | Hybrid | seeds + oracles |
| `secrets-hardcoded`, `dep-hallucination` | Static | scan only — not fuzz |

`randall hunt mistakes` lists the full catalog.

## Limits (v1)

- Raw HTTP/1.x over TCP (optional TLS) — not a full browser
- Minimal cookie jar (`fuzz.syncCookies` / http kind) — no redirect following
- Status matching via substrings (`HTTP/1.1 200`) and oracle `response_class` (`2xx` / `4xx` / `5xx`)
- Point at **your** app: set `target.executable` empty if the server is already running, or use Target Runtime to start it
- OpenAPI import not shipped yet (deferred — not a polish stub)
## Related

- [BUG_HUNTER.md](BUG_HUNTER.md) — mistake catalog + channels  
- [ORACLES.md](ORACLES.md) — judgment engine  
- `examples/http-simple/`, `examples/https-simple/`
