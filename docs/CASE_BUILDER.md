# Case builder — seeds, dictionaries, mutations

Build protocol-shaped **seeds** (CyberChef / Sulley-style blocks), harvest **dictionary** tokens, then let mutators explore variants — same mental model as AFL `in/` + `-x` dictionary.

## Workflow

1. Open **Fuzz → Case builder** (or CLI `randall case …`).
2. **Step 1 — Target profile:** create or pick a project. The YAML `name:` is the label in **Fuzz → Campaign → Target profile**. After create, that name shows up in the campaign dropdown.
3. Choose **TCP / UDP** (network) or **File format**. File format greys out host/port and asks for a parser executable + extension + starter format (XML, length frame, magic header, or blank custom).
4. **Step 2 — Build a seed:** blocks, network/file presets, or Import hex/text.
5. **Step 3 — Preview → Save as seed**, tune mutators (enable `dictionary` if you saved tokens).
6. Click **Open Campaign tab** (or switch manually), select your Target profile, Start.

Full YAML guide: [CUSTOM_TARGETS.md](CUSTOM_TARGETS.md).

## How do I fuzz a remote program?

1. Create a project with `kind: tcp` (or `udp`) and `transport.host` / `transport.port`.
2. Leave `target.executable` empty — Randfuzz will not start a local binary.
3. Add seeds + dictionary; enable mutators including `dictionary` / `havoc`.
4. Start the remote service yourself; start fuzz from Campaign or CLI.

Coverage-guided BB tracing needs a **local** instrumented binary. Remote-only campaigns still get mutational fuzzing, session graphs, and crash signals when the peer dies/resets.

## Blocks (ops)

| Block | Sulley / AFL analogue | Notes |
|-------|----------------------|-------|
| `static` | `s_static` | Keep as-is in the seed |
| `text` | `s_string` | Dictionary hint when role=fuzzable |
| `delim` | `s_delim` | Spaces, `/`, `:`, … |
| `quote` | quoted string | Wraps value in `"…"` |
| `utf16` | wide string | UTF-16LE (Windows) |
| `repeat` / `fill` | long `AAAA…` | Overflow-style pads |
| `pad` | align | Pad **next** block to N bytes |
| `hex` | raw bytes | Spaces/dashes ok |
| `interesting` | AFL interesting ints | `u8` / `u16le` / `u32be` … |
| `len-prefix` | size field | Applies to the **next** block |
| `cyclic` | unique pattern | Depth triage after a crash |
| `crlf` / `lf` / `null` | line endings / NUL | Protocol framing |
| `base64` / `random` | decode / entropy | Binary helpers |

**Role:** `static` vs `fuzzable` — only fuzzable `text`/`delim`/`quote`/`utf16` values are harvested as dictionary hints on save.

## Mutators (project YAML)

Toggle in Case builder checkboxes or edit `mutators:`:

| Mutator | Trick |
|---------|-------|
| `bitflip` | Single-bit corruption |
| `expand` / `truncate` | Length / buffer edges |
| `boundary` / `interesting` | Magic integers |
| `insert` / `havoc` | Random / stacked noise |
| `dictionary` | Inject tokens from YAML / dict file |
| `splice` / `arith` | Corpus crossover / byte math |
| `duplicate` | Repeat a random slice of the seed |
| `shuffle` | Swap two short spans inside the seed |

Saving dict tokens also ensures `dictionary` is listed in YAML and appends to the project's `dictionaryFile:` (default `dictionaries/{name}.txt`).

## Presets

- **HTTP GET** — request-line + Host
- **Overflow pad** — command + long `A` run (lab overflow shape)
- **Binary frame** — magic + length prefix + payload
- **FTP USER** — classic line protocol

## CLI

```powershell
randall case ops
randall case preview --static GET --delim " " --text /index.html --crlf
randall case new --name myservice --kind tcp --host 127.0.0.1 --port 8080
randall case update -p myservice --host 10.0.0.5 --port 8080 --desc "lab box"
randall case save-seed -p myservice --file my.bin --static PING --crlf
randall case mutators -p myservice --set bitflip,havoc,dictionary,expand
```

## Tips

- Start from a **valid** capture (Import text/hex or Load seed), then widen with `repeat` / `havoc`.
- Keep a small dictionary of magic strings (`%s%s%s`, `../`, command verbs).
- After a crash, use **cyclic** pads + stalk / analyze — not exploit builders.
- Protocol field models live under `projects/protocols/` — optional next step after dumb mutational seeds.
