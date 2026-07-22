# -*- coding: utf-8 -*-
# Randfuzz → Ghidra: run a generated *_stalk_layers.py or ghidra_import.py from an export dir
#@category Randfuzz
#@menupath Analysis.Randfuzz.Run export script
#@toolbar

from javax.swing import JFileChooser
import os

chooser = JFileChooser()
chooser.setDialogTitle("Pick Randfuzz *_stalk_layers.py or ghidra_import.py")
chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
if chooser.showOpenDialog(None) != JFileChooser.APPROVE_OPTION:
    print("Cancelled")
else:
    path = chooser.getSelectedFile().getAbsolutePath()
    if not os.path.isfile(path):
        raise Exception("Not a file: " + path)
    print("Randfuzz: running " + path)
    # Execute the generated script in this interpreter
    execfile(path) if "execfile" in dir(__builtins__) else exec(compile(open(path).read(), path, "exec"), globals())
