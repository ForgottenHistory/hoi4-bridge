# find RIP-relative LEA/MOV references to target RVAs; print containing function (from .pdata)
import sys, re, struct, bisect, pefile
pe = pefile.PE(sys.argv[1], fast_load=True); pe.parse_data_directories(directories=[3])
text = next(s for s in pe.sections if s.Name.startswith(b'.text'))
code = pe.__data__[text.PointerToRawData:text.PointerToRawData+text.Misc_VirtualSize]
base = text.VirtualAddress
targets = {int(t,16) for t in sys.argv[2:]}
funcs = sorted((e.struct.BeginAddress, e.struct.EndAddress) for e in pe.DIRECTORY_ENTRY_EXCEPTION)
starts = [f[0] for f in funcs]
def func_of(rva):
    i = bisect.bisect_right(starts, rva)-1
    return hex(funcs[i][0]) if i>=0 and funcs[i][0]<=rva<funcs[i][1] else '?'
for m in re.finditer(rb'[\x48\x4c][\x8d\x8b][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
    i = m.start(); disp = struct.unpack_from('<i', code, i+3)[0]
    tgt = base+i+7+disp
    if tgt in targets: print(hex(tgt), 'ref at', hex(base+i), 'func', func_of(base+i))
