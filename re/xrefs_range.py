# RIP-relative references to any address in [t, t+span) ; prints target offset, site, containing function
import sys, re, struct, bisect, pefile
pe = pefile.PE(sys.argv[1], fast_load=True); pe.parse_data_directories(directories=[3])
text = next(s for s in pe.sections if s.Name.startswith(b'.text'))
code = pe.__data__[text.PointerToRawData:text.PointerToRawData+text.Misc_VirtualSize]; base = text.VirtualAddress
funcs = sorted((e.struct.BeginAddress, e.struct.EndAddress) for e in pe.DIRECTORY_ENTRY_EXCEPTION); starts=[f[0] for f in funcs]
def fo(r):
    i=bisect.bisect_right(starts,r)-1; return hex(funcs[i][0]) if i>=0 and funcs[i][0]<=r<funcs[i][1] else '?'
span = int(sys.argv[2],16); targets = [int(t,16) for t in sys.argv[3:]]
# generic modrm rip-relative: any opcode followed by modrm with mod=00 rm=101; scan disp at every position
for i in range(len(code)-4):
    d = struct.unpack_from('<i', code, i)[0]
    for nxt in (4, 5):   # disp32 followed by 0 or 1 byte immediate (rough)
        tgt = base+i+nxt+d
        for t in targets:
            if t <= tgt < t+span and (code[i-1] & 0xC7) == 0x05:
                print(f'{t:#x}+{tgt-t:#x} at {base+i-1:#x} func {fo(base+i)}')
