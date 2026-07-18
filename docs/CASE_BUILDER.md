# Scare Floor — recipes, seeds, dictionaries

**Scare Floor** (UI name for the case builder) is where you prep scare attempts: editable **recipes** → queued **seeds** → Campaign fuzz shift.

Build protocol-shaped cases (CyberChef / Sulley-style blocks), save reusable recipes, harvest **dictionary** tokens, then let mutators explore variants — same mental model as AFL `in/` + `-x` dictionary.

## Workflow

1. Open **Fuzz → Scare Floor** (or CLI `randall case …`).
2. **Step 1 — Target profile:** create or pick a project. The YAML `name:` is the label in **Fuzz → Campaign → Target profile**.
3. Choose **TCP / UDP** (network) or **File format**. File format greys out host/port and asks for a parser executable + extension + starter format.
4. **Step 2 — Build a recipe:** blocks, presets, **upload a sample**, or paste hex/text. **Save recipe** keeps the editable block list under `recipes/` for reuse. **Append** stacks another saved recipe onto the current one.
5. **Queue seeds:** Preview → **Save as seed** (or **Save exact sample**). Multiple seeds = multiple cases in one campaign.
6. Tune mutators → **Campaign** → Start.

### Recipes (reuse & combine)

Recipes live under `{project}/recipes/*.json` — the editable block list, not the rendered seed.

| Action | Effect |
|--------|--------|
| **Save recipe** | Keep the Scare Floor recipe for later |
| **Load** (click name) | Replace the current recipe |
| **Append** | Stack another recipe onto the current one |
| **Save as seed** | Render blocks → `seeds/` for the Campaign queue |

```powershell
randall case recipes -p my-parser
randall case recipes -p my-parser --load overflow-trun
```

### Upload sample → fuzz template (file formats)

1. Create or pick a **file** Target profile (parser exe + extension).
2. Under **Build seed → Upload sample → template**, choose a valid file of that format.
3. Randfuzz sniffs magic / length-prefix / XML / text / **audio** (WAV, MP3, FLAC, Ogg, AIFF) and fills an editable recipe (static header + fuzzable body). Custom / unknown formats still get a magic + body split when possible.
4. Prefer **Save exact sample** for large/binary files so the seed matches the original bytes; use **Save as seed** when you edited the recipe.
5. Campaign → select the Target profile → Start.

### Network session (multi-PDU TCP)

On a **TCP** Target profile, Scare Floor can author a multi-message session (Phase 18):

1. Click **+ PDU** or preset **FTP login flow** (USER → PASS → STOR).
2. Edit each PDU’s blocks (select PDU in the strip). Choose **Mutate** = last / all / indices.
3. **Preview all PDUs** — per-message ASCII/hex.
4. **Apply to Campaign** — writes `seeds/{flow}_{PDU}.bin`, `sessionCommands`, and `sessionFlows` into the project YAML (`sessionFlowBias: 0.5`).
5. **Save recipe** keeps the session in `recipes/*.json` for reuse.

Single-blob recipes still work (HTTP GET, overflow pad, FTP USER). UDP stays single-datagram for now.

**Proxy → Scare Floor:** On the **Proxy** tab, select a capture → **Send to Scare Floor** (one PDU) or **All C→S → session** (every `client→target` message as ordered PDUs). Requires a TCP Target profile selected under Scare Floor → Working on project.

### Byte editor (Step 3)

After **Preview**, the Scare Floor editor loads the full buffer (ASCII or Hex):

| Feature | How |
|---------|-----|
| **Find / Replace** | Toolbar fields · **F3** find next · **Ctrl+F** / **Ctrl+H** focus find |
| **Replace all** | Same find needle across the buffer |
| **Show invisibles** | Toggle spaces (`·`), tabs (`→`), CR/LF (`␍` `␊` `␤`) — off by default |
| **Column mode** | Checkbox → set col start/end + value → **Apply to lines** |
| **Ctrl+Alt + key** | Overwrite that column on every selected line (or all lines) — Notepad++-style |
| **Apply to recipe** | Writes the edited buffer back as one fuzzable `hex` block |

Use Hex mode for binary/audio; ASCII (Latin-1) for text protocols.

CLI:

```powershell
randall case from-file -p my-parser --file C:\samples\good.bin
randall case from-file -p my-parser --file C:\samples\good.bin --exact
```

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
- **WAV audio** — minimal RIFF/WAVE + fmt + data (file targets)
- File starters also: XML, length frame, magic + body, blank custom

## CLI

```powershell
randall case ops
randall case preview --static GET --delim " " --text /index.html --crlf
randall case new --name myservice --kind tcp --host 127.0.0.1 --port 8080
randall case update -p myservice --host 10.0.0.5 --port 8080 --desc "lab box"
randall case save-seed -p myservice --file my.bin --static PING --crlf
randall case from-file -p my-parser --file sample.bin --exact
randall case mutators -p myservice --set bitflip,havoc,dictionary,expand
```

## Tips

- Start from a **valid** capture (Import text/hex or Load seed), then widen with `repeat` / `havoc`.
- Keep a small dictionary of magic strings (`%s%s%s`, `../`, command verbs).
- After a crash, use **cyclic** pads + stalk / analyze — not exploit builders.
- Protocol field models live under `projects/protocols/` — optional next step after dumb mutational seeds.
