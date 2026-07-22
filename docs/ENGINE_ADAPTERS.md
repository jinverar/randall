# External engine adapters (AFL++ / honggfuzz)

Randfuzz’s default engine is **generation + stalking** (block models, sessions, DynamoRIO).  
When you need **market-grade coverage throughput** on a real parse entry, opt into an external engine per project:

| `fuzz.engine` | Binary | What you get |
|---------------|--------|--------------|
| `randall` (default) | — | Own mutators, sessions, stalk, triage UI |
| `aflpp` | `afl-fuzz` (AFL++) | Fork-server + coverage bitmap + optional CMPLOG/QEMU |
| `honggfuzz` | `honggfuzz` | Fast Linux coverage engine |

Crashes and queue corpora **sync back** into Randfuzz (`data/crashes/…`, `data/corpus/…`) so scream canisters / triage still work.

> **Authorized targets only.** These adapters are for software you own or have written permission to test — not for unlicensed third-party zero-click hunting.

## Install

```bash
scripts/install-linux-tools.sh --engines   # or: apt install afl++
# optional: apt install honggfuzz
dotnet run --project src/Randall.Cli -- doctor -c projects/aflpp-harness.yaml --platform linux
```

## Project shape (file harness)

External engines drive a **file/harness** target (`kind: file`) that reads `@@` (AFL++) or `___FILE___` (honggfuzz).  
For network “zero-click” surfaces, wrap the **parse function** in a harness that feeds one PDU from a file — that is how serious custom fuzzers beat raw packet blast.

```yaml
name: my-parser
kind: file
target:
  executable: ../targets/local/my_harness   # afl-clang-fast build
  args: ["@@"]
fuzz:
  engine: aflpp
  engineTimeoutSec: 3600          # 0 = run until Stop / Ctrl-C
  engineExtraArgs: ""             # e.g. "-Q" QEMU, or CMPLOG flags
  corpusDir: ../data/corpus/my-parser
  crashesDir: ../data/crashes/my-parser
seeds:
  - seeds/valid_sample.bin
```

Build the harness with AFL instrumentation when you can:

```bash
afl-clang-fast -O2 -o targets/local/my_harness harness.c
# or afl-clang-fast++ for C++
```

Smoke test (repo demo):

```bash
# Prefer afl-clang-fast; gcc also works for a quick crash demo
afl-clang-fast -O2 -o targets/aflpp-harness/crashy_parse targets/aflpp-harness/crashy_parse.c \
  || gcc -O2 -o targets/aflpp-harness/crashy_parse targets/aflpp-harness/crashy_parse.c

dotnet run --project src/Randall.Cli -- fuzz -c projects/aflpp-harness.yaml
dotnet run --project src/Randall.Cli -- crashes -p aflpp-harness
```

## What this is (and is not)

| Is | Is not |
|----|--------|
| Real AFL++/honggfuzz campaign under Randfuzz | A claim that Randfuzz alone beats AFL++ exec/s |
| Path for custom, authorized product parsers | A Zerodium-ready exploit factory |
| Crash → Randfuzz triage (registers/offsets) | Automatic shellcode / payload development |

Stay inside your triage threshold: harvest screams, confirm register control, count offsets — no weaponized payloads unless you explicitly change that policy.

## Network / zero-click shaped work

1. Identify the **unsolicited parse path** (codec, message blob, RPC stub).
2. Write a **file harness** that calls that path (libFuzzer/`LLVMFuzzerTestOneInput` style is ideal).
3. Seed with valid-looking PDUs; enable `fuzz.engine: aflpp`.
4. Keep structure-aware seeds in Randfuzz (`projects/local/`, Scare Floor) and let AFL++ grind coverage.

TCP session fuzzing without a harness stays on `fuzz.engine: randall` (generation + stalk). Hybrid workflow: model sessions in Randfuzz → dump interesting PDUs as seeds → AFL++ harness campaign.

## Doctor / UI

- `randall doctor -c projects/….yaml` fails preflight if `aflpp`/`honggfuzz` is selected but missing.
- Optional engines remain **warn**-level in the Linux toolchain grid when not selected.
