# For each call to a target function, print string literals referenced in the ~0x60 bytes before the call
import sys, re, struct, pefile, capstone
pe = pefile.PE(sys.argv[1], fast_load=True); img = pe.get_memory_mapped_image()
text = next(s for s in pe.sections if s.Name.startswith(b'.text')); base = text.VirtualAddress
code = img[base:base+text.Misc_VirtualSize]
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
def s_at(r):
    e = img.find(b'\0', r, r+200); s = img[r:e]
    return s.decode('latin1') if 2 <= len(s) and all(32 <= c < 127 for c in s) else None
for tgt in (int(t,16) for t in sys.argv[2:]):
    print(f'== calls to {tgt:#x}')
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if base+i+5+struct.unpack_from('<i', code, i+1)[0] != tgt: continue
        site = base+i; strs = []
        # disassemble a window ending at the call; try a few start offsets to sync
        for back in range(0x70, 0x40, -1):
            ins = list(md.disasm(img[site-back:site+5], site-back))
            if ins and ins[-1].address == site: break
        for x in ins:
            mm = re.search(r'\[rip \+ (0x[0-9a-f]+)\]', x.op_str)
            if mm:
                s = s_at(x.address + x.size + int(mm.group(1), 16))
                if s: strs.append(s)
        print(f'  {site:#x}: {strs[-3:]}')
