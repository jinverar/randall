#!/usr/bin/env python3
"""Convert simple boofuzz example scripts to Randall YAML + Scare Floor recipes.

Usage:
  python scripts/import-boofuzz.py examples/fixtures/ftp_simple.py -o projects/imported/ftp
  python scripts/import-boofuzz.py path/to/ftp_simple.py -o projects/imported/ftp --recipe
  python scripts/import-boofuzz.py path/to/ftp_simple.py -o projects/protocols/packs/my-ftp --pack

Emits:
  protocols/*.yaml + project.yaml  (always)
  recipe.json                      (--recipe or --pack)
  pack.yaml                        (--pack)
"""
from __future__ import annotations

import argparse
import json
import re
import textwrap
from pathlib import Path


def parse_requests(source: str) -> dict[str, list[dict]]:
    requests: dict[str, list[dict]] = {}
    for match in re.finditer(
        r'Request\(\s*"([^"]+)"\s*,\s*children=\(\s*(.*?)\s*\)\s*,?\s*\)',
        source,
        re.DOTALL,
    ):
        name, body = match.group(1), match.group(2)
        blocks: list[dict] = []
        for child in re.finditer(
            r'(String|Delim|Static|Group)\(\s*name="([^"]+)"(?:,\s*default_value="([^"]*)")?(?:,\s*values=\[([^\]]+)\])?',
            body,
        ):
            kind, field, default, values = child.groups()
            kind = kind.lower()
            if kind == "group":
                blocks.append({
                    "type": "choices",
                    "name": field,
                    "values": [v.strip().strip('"') for v in (values or "").split(",") if v.strip()],
                })
            elif kind == "delim":
                blocks.append({"type": "delim", "name": field, "value": default or " ", "mutable": False})
            elif kind == "static":
                val = default or ""
                blocks.append({"type": "static", "value": val.replace("\\r", "\r").replace("\\n", "\n")})
            else:
                blocks.append({
                    "type": "string",
                    "name": field,
                    "value": default or "",
                    "mutable": True,
                })
        requests[name] = blocks
    return requests


def parse_connects(source: str) -> list[list[str]]:
    flows: list[list[str]] = []
    for line in source.splitlines():
        m = re.search(r'session\.connect\(([^)]+)\)', line)
        if not m:
            continue
        parts = [p.strip().strip('"') for p in m.group(1).split(",")]
        if len(parts) == 1:
            flows.append([parts[0]])
        else:
            flows.append([parts[0], parts[1]])
    return flows


def emit_protocol(name: str, blocks: list[dict]) -> str:
    lines = [f"name: {name}", "description: imported from boofuzz", "blocks:"]
    for b in blocks:
        t = b["type"]
        if t == "static":
            val = b["value"].replace("\r", "\\r").replace("\n", "\\n")
            lines.append(f'  - type: static\n    value: "{val}"')
        elif t == "delim":
            lines.append(f'  - type: delim\n    name: {b["name"]}\n    value: "{b["value"]}"\n    mutable: false')
        elif t == "choices":
            vals = ", ".join(f'"{v}"' for v in b["values"])
            lines.append(f'  - type: choices\n    name: {b["name"]}\n    values: [{vals}]')
        else:
            val = b.get("value", "")
            lines.append(
                f'  - type: string\n    name: {b["name"]}\n    value: "{val}"\n    mutable: true'
            )
    return "\n".join(lines) + "\n"


def emit_project(requests: dict[str, list[dict]], flows: list[list[str]], host: str, port: int) -> str:
    cmds = []
    for name in requests:
        cmds.append(
            f"  - name: {name.upper()}\n    model: protocols/{name.lower()}.yaml\n    readBanner: true"
        )
    flow_yaml = ""
    if flows:
        flow_yaml = "sessionFlows:\n"
        for i, flow in enumerate(flows):
            steps = ", ".join(n.upper() for n in flow)
            flow_yaml += f"  - name: flow_{i}\n    steps: [{steps}]\n"
    return textwrap.dedent(
        f"""\
        name: imported-boofuzz
        description: Imported from boofuzz script
        kind: tcp
        transport:
          type: tcp
          host: {host}
          port: {port}
          receiveTimeoutMs: 2000
        sessionCommands:
        {chr(10).join(cmds)}
        {flow_yaml}fuzz:
          maxIterations: 500
          mode: exhaustive
          corpusDir: ../../data/corpus/imported
          crashesDir: ../../data/crashes/imported
        mutators:
          - bitflip
          - havoc
          - boundary
        """
    )


def block_to_recipe_op(b: dict) -> dict:
    t = b["type"]
    if t == "static":
        val = b["value"]
        if val == "\r\n":
            return {"op": "crlf", "role": "static"}
        if val == "\n":
            return {"op": "lf", "role": "static"}
        if val == "\0":
            return {"op": "null", "role": "static"}
        return {"op": "static", "value": val.replace("\r", "\\r").replace("\n", "\\n"), "role": "static"}
    if t == "delim":
        return {"op": "delim", "value": b.get("value") or " ", "role": "static"}
    if t == "choices":
        vals = b.get("values") or [""]
        return {"op": "text", "value": vals[0], "role": "fuzzable"}
    return {"op": "text", "value": b.get("value") or "", "role": "fuzzable"}


def emit_recipe(requests: dict[str, list[dict]], name: str = "imported-boofuzz") -> dict:
    session_steps = []
    for req_name, blocks in requests.items():
        session_steps.append({
            "name": req_name.upper(),
            "readBanner": True,
            "expectResponse": "",
            "blocks": [block_to_recipe_op(b) for b in blocks],
        })
    return {
        "name": name,
        "description": "Imported from boofuzz -> Scare Floor session recipe",
        "kind": "session",
        "mutateStep": "last",
        "steps": [],
        "sessionSteps": session_steps,
    }


def emit_pack_yaml(pack_id: str, name: str, proto_names: list[str]) -> str:
    refs = "\n".join(f"  - protocols/{n.lower()}.yaml" for n in proto_names)
    return textwrap.dedent(
        f"""\
        id: {pack_id}
        name: {name}
        description: Imported from boofuzz (Scare Floor pack)
        kind: session
        recipe: recipe.json
        protocols:
        {refs}
        """
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Boofuzz → Randall YAML / Scare Floor recipe importer")
    ap.add_argument("input", type=Path, help="boofuzz .py example")
    ap.add_argument("-o", "--output", type=Path, required=True, help="output directory")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--recipe", action="store_true", help="also write recipe.json for Scare Floor")
    ap.add_argument("--pack", action="store_true",
                    help="write pack.yaml + recipe.json + protocols/ (protocol pack layout)")
    args = ap.parse_args()

    source = args.input.read_text(encoding="utf-8")
    requests = parse_requests(source)
    flows = parse_connects(source)
    if not requests:
        raise SystemExit("No Request(...) blocks found — try ftp_simple.py or http_simple.py")

    out = args.output
    proto_dir = out / "protocols"
    proto_dir.mkdir(parents=True, exist_ok=True)
    for name, blocks in requests.items():
        (proto_dir / f"{name.lower()}.yaml").write_text(emit_protocol(name, blocks), encoding="utf-8")

    if not args.pack:
        flow_steps = [[n.upper() for n in f] for f in flows]
        (out / "project.yaml").write_text(
            emit_project(requests, flow_steps, args.host, args.port),
            encoding="utf-8",
        )

    write_recipe = args.recipe or args.pack
    if write_recipe:
        recipe = emit_recipe(requests, name=out.name or "imported-boofuzz")
        (out / "recipe.json").write_text(json.dumps(recipe, indent=2) + "\n", encoding="utf-8")

    if args.pack:
        pack_id = re.sub(r"[^a-z0-9\-]+", "-", out.name.lower()).strip("-") or "imported"
        (out / "pack.yaml").write_text(
            emit_pack_yaml(pack_id, pack_id, list(requests.keys())),
            encoding="utf-8",
        )

    bits = [f"{len(requests)} protocol(s)"]
    if not args.pack:
        bits.append("project.yaml")
    if write_recipe:
        bits.append("recipe.json")
    if args.pack:
        bits.append("pack.yaml")
    print(f"Wrote {', '.join(bits)} -> {out}")
    if write_recipe:
        print("Tip: Scare Floor -> Protocol pack -> Load pack (if under projects/protocols/packs/),")
        print("     or copy recipe.json into a project's recipes/ folder.")


if __name__ == "__main__":
    main()
