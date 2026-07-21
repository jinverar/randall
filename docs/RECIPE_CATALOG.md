# Recipe Catalog

A browsable library of fuzzing recipes covering the target classes that dominate exploit‑db and
commercial fuzzers (beSTORM / Defensics): binary **file formats**, text/config formats, **network
protocols**, and **web‑application** payload classes. Each recipe carries a magic‑byte / starter seed,
category tags (exploit‑db style: `buffer-overflow`, `heap-overflow`, `format-string`, `xxe`,
`sql-injection`, …), suggested mutators, and a per‑class dictionary — so you can go from "pick a
target class" to a ready‑to‑fuzz project in one click.

> The catalog is table‑driven (`RecipeCatalog`), so it scales toward thousands of recipes without new
> code — add rows, not plumbing.

## Categories (current)

Image · Audio · Video · Archive · Document · Font · Playlist · Data/Config · Executable/System ·
Mail/Transfer · Web server · Media/Streaming · Naming/Directory · Database · IoT/ICS · Remote access ·
Web application.

Examples: JPEG/PNG/GIF/TIFF/BMP/WebP/SVG, WAV/MP3/OGG/FLAC/MIDI, MP4/AVI/MKV/FLV, ZIP/GZIP/TAR/RAR/7z,
PDF/OLE/OOXML/RTF, TTF/OTF/WOFF, M3U/PLS/SRT, XML/JSON/YAML/CSV/SQLite/PCAP, ELF/PE/LNK/ANI,
FTP/SMTP/IMAP/HTTP/RTSP/SIP/DNS/DHCP/TFTP/SNMP/LDAP/NTP, Redis/MySQL/Postgres/MongoDB,
MQTT/Modbus/DNP3/CoAP, Telnet/IRC/VNC/RDP/SMB/SOCKS, and web classes SQLi/XSS/XXE/SSTI/traversal/cmdi.

## Web UI

**Fuzz → Scare Floor → Recipe catalog**: filter by category, search by name/tag, and click **Create
project**. The new project appears in the Target profile dropdowns immediately, seeded with the
recipe's starter bytes, mutators, and dictionary.

## CLI

```bash
randall case catalog --categories                 # list categories + counts
randall case catalog --category Image             # browse a category
randall case catalog --search buffer-overflow     # search by name / tag
randall case catalog --instantiate file-pdf --name lab-pdf   # create a project
randall case catalog --instantiate net-ftp                    # name defaults to the recipe id
```

## API

- `GET /api/case/catalog?category=&search=` → `{ count, categories, entries[] }`
- `GET /api/case/catalog/{id}` → full detail (seed hex preview + dictionary)
- `POST /api/case/catalog/instantiate` `{ id, name?, localFolder? }` → creates the project

## What instantiation produces

For recipe `<id>`:
- a project profile (`projects/local/<name>.yaml`; `--public` for `projects/`),
- a starter seed (`seeds/<id>_seed.<ext>`) with the format's magic bytes or a sample request,
- the recipe's suggested `mutators:`,
- the per‑class `dictionary` tokens (overflow / format‑string / SQLi / XSS / traversal / …).

Then queue seeds and run it like any Scare Floor target (see [CASE_BUILDER.md](CASE_BUILDER.md)). File
recipes need a local parser executable as the target; network recipes point at `127.0.0.1:<port>`.
