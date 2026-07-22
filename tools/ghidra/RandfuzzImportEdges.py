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
    painted = 0
    skipped = 0
    with open(path, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 2:
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
    print("RandfuzzImportEdges: painted %d, skipped %d from %s" % (painted, skipped, path))
