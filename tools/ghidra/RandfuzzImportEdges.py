# -*- coding: utf-8 -*-
# Randfuzz → Ghidra: import coverage_edges.txt (moduleId:0xstart:size)
# Install: copy into your Ghidra scripts dir, or Script Manager → Script Directories.
#@category Randfuzz
#@menupath Analysis.Randfuzz.Import coverage edges
#@toolbar

from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.program.model.address import AddressSet
from java.awt import Color
from javax.swing import JFileChooser
import os

service = state.getTool().getService(ColorizingService)
if service is None:
    raise Exception("ColorizingService unavailable — open CodeBrowser")

chooser = JFileChooser()
chooser.setDialogTitle("Randfuzz coverage_edges.txt")
if chooser.showOpenDialog(None) != JFileChooser.APPROVE_OPTION:
    print("Cancelled")
else:
    path = chooser.getSelectedFile().getAbsolutePath()
    color = Color(0, 200, 80)
    base = currentProgram.getImageBase()
    prog_name = currentProgram.getName()
    prog_path = currentProgram.getExecutablePath() or ""
    painted = 0
    skipped = 0
    foreign = 0

    # Optional modules.txt beside edges: id\tpath\tstart\tend
    allow_ids = set()
    modules_path = os.path.join(os.path.dirname(path), "modules.txt")
    if os.path.isfile(modules_path):
        with open(modules_path, "r") as mf:
            for mline in mf:
                mline = mline.strip()
                if not mline or mline.startswith("#"):
                    continue
                parts = mline.split("\t")
                if len(parts) < 2:
                    continue
                mid, mpath = parts[0], parts[1]
                leaf = os.path.basename(mpath.replace("\\", "/"))
                if leaf.lower() == prog_name.lower() or (
                    prog_path and leaf.lower() == os.path.basename(prog_path.replace("\\", "/")).lower()
                ):
                    allow_ids.add(mid)
                    if len(parts) >= 3 and parts[2]:
                        try:
                            pref = int(parts[2], 16) if parts[2].lower().startswith("0x") else int(parts[2])
                            if pref != long(base.getOffset()):
                                print("Randfuzz: preferred base 0x%x vs imageBase %s — using imageBase+RVA" % (pref, base))
                        except:
                            pass
        if allow_ids:
            print("RandfuzzImportEdges: filtering to module id(s) %s" % sorted(allow_ids))

    with open(path, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 2:
                continue
            mid = parts[0]
            if allow_ids and mid not in allow_ids:
                foreign += 1
                continue
            rva_s = parts[1]
            if rva_s.lower().startswith("0x"):
                rva_s = rva_s[2:]
            try:
                rva = int(rva_s, 16)
            except:
                continue
            size = 1
            if len(parts) >= 3:
                try:
                    size = max(1, int(parts[2]))
                except:
                    size = 1
            start = base.add(rva)
            if service.getBackgroundColor(start) is not None:
                skipped += 1
                continue
            end = start.add(size - 1)
            service.setBackgroundColor(AddressSet(start, end), color)
            painted += 1
    print("RandfuzzImportEdges: painted %d, skipped %d, other-module %d from %s" % (painted, skipped, foreign, path))
