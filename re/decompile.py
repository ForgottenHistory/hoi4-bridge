# Usage: decompile.py <rva-hex> [<rva-hex> ...]  -> prints Ghidra's C decompilation (read-only, project not modified)
import os, sys, pyghidra
# Ghidra and its project live in the RE workbench, outside this repo.
WB = os.environ.get("HOI4_RE_WORKBENCH", r"C:\Users\Albin\hoi4-console-bridge")
pyghidra.start(install_dir=os.path.join(WB, "tools", "ghidra_12.1.4_PUBLIC"))
from ghidra.base.project import GhidraProject
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
proj = GhidraProject.openProject(os.path.join(WB, "ghidra-project"), "hoi4", True)
prog = proj.openProgram("/", "hoi4_1.19.3.exe", True)
try:
    di = DecompInterface(); di.openProgram(prog)
    fm = prog.getFunctionManager(); base = prog.getImageBase()
    for a in sys.argv[1:]:
        f = fm.getFunctionContaining(base.add(int(a, 16)))
        print(f"// ===== {f.getName()} @ {f.getEntryPoint()}")
        r = di.decompileFunction(f, 120, ConsoleTaskMonitor())
        print(r.getDecompiledFunction().getC() if r.decompileCompleted() else r.getErrorMessage())
finally:
    proj.close()
