# -*- coding: utf-8 -*-
# Randfuzz → Ghidra: export randall-analysis.json (static target map for Oracle/stalk).
# Headless: analyzeHeadless ... -postScript RandfuzzExportAnalysis.py <output.json>
# GUI: Script Manager → run on an open program (file chooser if no arg).
#@category Randfuzz
#@menupath Analysis.Randfuzz.Export randall-analysis.json

from __future__ import print_function
import json
import os
import time

from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import RefType, SymbolType
from ghidra.util.task import ConsoleTaskMonitor
from javax.swing import JFileChooser

# Input sources and dangerous sinks (SaTC-style, aligned with Randall BinarySurfaceMap)
INPUT_SOURCES = [
    "recv", "recvfrom", "read", "fread", "gets", "getenv",
    "ReadFile", "InternetReadFile", "WSARecv", "accept", "fgets",
]
SINKS = {
    "memcpy": 90, "memmove": 85, "strcpy": 95, "strncpy": 80, "strcat": 95,
    "sprintf": 90, "vsprintf": 92, "snprintf": 70, "scanf": 85, "sscanf": 80,
    "gets": 100, "malloc": 60, "realloc": 65, "free": 55,
    "system": 95, "popen": 90, "CreateProcess": 95, "ShellExecute": 90,
    "LoadLibrary": 75, "VirtualAlloc": 70, "WriteFile": 65,
}


def addr_hex(addr):
    if addr is None:
        return ""
    return "0x%x" % (addr.getOffset() & 0xFFFFFFFFFFFFFFFF)


def sym_name(sym):
    if sym is None:
        return ""
    return sym.getName()


def is_input_source(name):
    if not name:
        return False
    n = name.lower()
    for tip in INPUT_SOURCES:
        if tip.lower() in n:
            return True
    return False


def is_dangerous(name):
    if not name:
        return False
    n = name.lower()
    for tip in SINKS:
        if tip.lower() in n:
            return True
    return False


def sink_related(name):
    return is_dangerous(name) or is_input_source(name)


def sink_risk(name):
    if not name:
        return 50
    n = name.lower()
    for tip, risk in SINKS.items():
        if tip.lower() in n:
            return risk
    return 50


def compute_priority(bb_count, complexity, dangerous, input_reachable, caller_count):
    score = 0
    score += min(28, complexity / 2)
    score += min(22, bb_count / 3)
    score += min(30, len(dangerous) * 10)
    if input_reachable:
        score += 12
    score += min(10, caller_count)
    if score > 100:
        score = 100
    if score < 0:
        score = 0
    return int(score)


def count_basic_blocks(func, bbm, monitor):
    body = func.getBody()
    if body is None or body.isEmpty():
        return 0
    blocks = bbm.getCodeBlocksContaining(body, monitor)
    count = 0
    while blocks.hasNext():
        blocks.next()
        count += 1
    return count


def export_function_cfg(func, bbm, monitor):
    body = func.getBody()
    if body is None or body.isEmpty():
        return {"blocks": []}

    code_blocks = []
    addr_to_idx = {}
    iter_blocks = bbm.getCodeBlocksContaining(body, monitor)
    while iter_blocks.hasNext():
        cb = iter_blocks.next()
        start = addr_hex(cb.getMinAddress())
        size = int(cb.getMaxAddress().subtract(cb.getMinAddress())) + 1
        addr_to_idx[start] = len(code_blocks)
        code_blocks.append({
            "address": start,
            "size": size,
            "successors": [],
            "predecessors": [],
        })

    # Re-walk to wire edges (BasicBlockModel iterator is not indexable)
    iter_blocks = bbm.getCodeBlocksContaining(body, monitor)
    while iter_blocks.hasNext():
        cb = iter_blocks.next()
        start = addr_hex(cb.getMinAddress())
        if start not in addr_to_idx:
            continue
        idx = addr_to_idx[start]
        block = code_blocks[idx]

        dest_it = bbm.getDestinations(cb, monitor)
        while dest_it.hasNext():
            ref = dest_it.next()
            dest = ref.getDestinationBlock()
            if dest is None:
                continue
            ds = addr_hex(dest.getMinAddress())
            if ds in addr_to_idx and ds not in block["successors"]:
                block["successors"].append(ds)
                di = addr_to_idx[ds]
                if start not in code_blocks[di]["predecessors"]:
                    code_blocks[di]["predecessors"].append(start)

        src_it = bbm.getSources(cb, monitor)
        while src_it.hasNext():
            ref = src_it.next()
            src = ref.getSourceBlock()
            if src is None:
                continue
            ss = addr_hex(src.getMinAddress())
            if ss in addr_to_idx and ss not in block["predecessors"]:
                block["predecessors"].append(ss)
                si = addr_to_idx[ss]
                if start not in code_blocks[si]["successors"]:
                    code_blocks[si]["successors"].append(start)

    return {"blocks": code_blocks}


def callee_names(func, listing, fm):
    names = set()
    start = func.getEntryPoint()
    end = func.getBody().getMaxAddress()
    addr = start
    while addr is not None and addr.compareTo(end) <= 0:
        cu = listing.getCodeUnitAt(addr)
        if cu is not None:
            for ref in cu.getReferencesFrom():
                if ref.getReferenceType().isCall():
                    to = ref.getToAddress()
                    callee = fm.getFunctionAt(to)
                    if callee is not None:
                        names.add(callee.getName())
                    else:
                        sym = getSymbolAt(to)
                        if sym is not None:
                            names.add(sym.getName())
        addr = addr.next()
    return sorted(names)


def collect_call_edges(func, listing, fm):
    edges = []
    start = func.getEntryPoint()
    end = func.getBody().getMaxAddress()
    caller = func.getName()
    addr = start
    while addr is not None and addr.compareTo(end) <= 0:
        cu = listing.getCodeUnitAt(addr)
        if cu is not None:
            for ref in cu.getReferencesFrom():
                if not ref.getReferenceType().isCall():
                    continue
                to = ref.getToAddress()
                callee_name = None
                callee = fm.getFunctionAt(to)
                if callee is not None:
                    callee_name = callee.getName()
                else:
                    sym = getSymbolAt(to)
                    if sym is not None:
                        callee_name = sym.getName()
                if callee_name is None:
                    continue
                edges.append({
                    "caller": caller,
                    "callee": callee_name,
                    "callSite": addr_hex(ref.getFromAddress()),
                })
        addr = addr.next()
    return edges


def caller_count(func, ref_mgr):
    entry = func.getEntryPoint()
    n = 0
    for ref in ref_mgr.getReferencesTo(entry):
        if ref.getReferenceType().isCall():
            n += 1
    return n


def resolve_output_path():
    args = getScriptArgs()
    if args and len(args) > 0 and args[0]:
        return args[0]
    chooser = JFileChooser()
    chooser.setDialogTitle("Save randall-analysis.json")
    chooser.setSelectedFile(java.io.File("randall-analysis.json"))
    if chooser.showSaveDialog(None) != JFileChooser.APPROVE_OPTION:
        raise Exception("Cancelled")
    path = chooser.getSelectedFile().getAbsolutePath()
    if not path.lower().endswith(".json"):
        path += ".json"
    return path


def export_analysis(output_path):
    prog = currentProgram
    if prog is None:
        raise Exception("No program open")

    fm = prog.getFunctionManager()
    listing = prog.getListing()
    ref_mgr = prog.getReferenceManager()
    sym_table = prog.getSymbolTable()
    bbm = BasicBlockModel(prog)
    monitor = ConsoleTaskMonitor()

    imports_list = []
    exports_list = []
    sink_index = {}
    xrefs = []
    call_graph = []

    # External / import symbols
    for sym in sym_table.getExternalSymbols():
        if sym.getSymbolType() != SymbolType.FUNCTION:
            continue
        name = sym.getName()
        ext_loc = sym.getExternalLocation()
        lib = ext_loc.getLibraryName() if ext_loc is not None else ""
        addr = addr_hex(sym.getAddress()) if sym.getAddress() is not None else ""
        imports_list.append({"library": lib, "name": name, "address": addr})
        if sink_related(name):
            kind = "input" if is_input_source(name) else "sink"
            sink_index[name] = {
                "name": name,
                "address": addr,
                "kind": kind,
                "risk": sink_risk(name),
                "callers": [],
            }

    # Exports
    for sym in sym_table.getSymbols(prog.getMinAddress(), SymbolType.FUNCTION):
        if sym.isExternal():
            continue
        if sym.getSource() == ghidra.program.model.symbol.SourceType.DEFAULT:
            continue
        exports_list.append({"name": sym.getName(), "address": addr_hex(sym.getAddress())})

    functions = []
    input_reachable_funcs = set()

    for func in fm.getFunctions(True):
        name = func.getName()
        entry = func.getEntryPoint()
        body = func.getBody()
        size = int(body.getNumAddresses()) if body is not None else 0
        bb_count = count_basic_blocks(func, bbm, monitor)
        complexity = bb_count + max(0, size / 16)
        callers = caller_count(func, ref_mgr)
        callees = callee_names(func, listing, fm)
        dangerous = [c for c in callees if is_dangerous(c)]
        reaches_input = any(is_input_source(c) for c in callees)
        if reaches_input:
            input_reachable_funcs.add(name)

        priority = compute_priority(bb_count, complexity, dangerous, reaches_input, callers)
        cfg = export_function_cfg(func, bbm, monitor)
        call_graph.extend(collect_call_edges(func, listing, fm))

        functions.append({
            "name": name,
            "address": addr_hex(entry),
            "size": size,
            "basicBlockCount": bb_count,
            "complexity": int(complexity),
            "callerCount": callers,
            "calleeCount": len(callees),
            "inputReachable": reaches_input,
            "hasDangerousCalls": len(dangerous) > 0,
            "dangerousCalls": dangerous,
            "fuzzPriority": priority,
            "cfg": cfg,
        })

        for callee in callees:
            if sink_related(callee):
                xrefs.append({
                    "fromFunction": name,
                    "fromAddress": addr_hex(entry),
                    "toSymbol": callee,
                    "toAddress": "",
                    "refKind": "call",
                })
                if callee in sink_index:
                    if name not in sink_index[callee]["callers"]:
                        sink_index[callee]["callers"].append(name)

    # Propagate input reachability backward
    changed = True
    while changed:
        changed = False
        for fn in functions:
            if fn["inputReachable"]:
                continue
            for xr in xrefs:
                if xr["fromFunction"] != fn["name"]:
                    continue
                if xr["toSymbol"] in input_reachable_funcs or is_input_source(xr["toSymbol"]):
                    fn["inputReachable"] = True
                    fn["fuzzPriority"] = compute_priority(
                        fn["basicBlockCount"], fn["complexity"], fn["dangerousCalls"], True, fn["callerCount"])
                    input_reachable_funcs.add(fn["name"])
                    changed = True
                    break

    sinks = sorted(sink_index.values(), key=lambda s: (-s["risk"], s["name"]))

    # Dedupe call graph
    seen_cg = set()
    deduped_cg = []
    for edge in call_graph:
        key = (edge["caller"], edge["callee"], edge["callSite"])
        if key in seen_cg:
            continue
        seen_cg.add(key)
        deduped_cg.append(edge)

    exe = prog.getExecutablePath()
    if exe is None or exe == "":
        exe = prog.getName()

    doc = {
        "version": "2",
        "binary": exe,
        "binarySha256": None,
        "imageBase": addr_hex(prog.getImageBase()),
        "exportedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "exporter": "RandfuzzExportAnalysis.py",
        "functions": functions,
        "imports": imports_list,
        "exports": exports_list,
        "sinks": sinks,
        "xrefs": xrefs,
        "callGraph": deduped_cg,
    }

    with open(output_path, "w") as fh:
        json.dump(doc, fh, indent=2)

    print("Randfuzz: wrote %s (%d functions, %d sinks, %d call-graph edges, v2 full CFG)" % (
        output_path, len(functions), len(sinks), len(deduped_cg)))
    return doc


output = resolve_output_path()
export_analysis(output)
