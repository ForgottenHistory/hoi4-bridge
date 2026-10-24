import sys, struct, bisect, pefile, capstone
pe = pefile.PE(sys.argv[1], fast_load=True); pe.parse_data_directories(directories=[3])
img = pe.get_memory_mapped_image()
funcs = sorted((e.struct.BeginAddress, e.struct.EndAddress) for e in pe.DIRECTORY_ENTRY_EXCEPTION)
starts=[f[0] for f in funcs]
def fn(rva):
    i=bisect.bisect_right(starts,rva)-1
    return funcs[i] if i>=0 and funcs[i][0]<=rva<funcs[i][1] else None
def strat(rva):
    if not (0x2707000<=rva<0x35e8000): return None
    end=img.find(b'\0',rva,rva+120); s=img[rva:end]
    return s.decode('latin1') if len(s)>=3 and all(32<=c<127 for c in s) else None
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=False
start=int(sys.argv[2],16); n=int(sys.argv[3]) if len(sys.argv)>3 else 120
f=fn(start); end=f[1] if f else start+0x400
for k,ins in enumerate(md.disasm(img[start:end], start)):
    if k>=n: break
    extra=''
    if 'rip' in ins.op_str and '[rip' in ins.op_str:
        try:
            d=int(ins.op_str.split('rip')[1].split(']')[0].replace(' ',''),16); t=ins.address+ins.size+d
            s=strat(t); extra=f'  ; ->{hex(t)} {s!r}' if s else f'  ; ->{hex(t)}'
        except Exception: pass
    if ins.mnemonic=='call' and ins.op_str.startswith('0x'): extra=f'  ; func {ins.op_str}'
    print(hex(ins.address), ins.mnemonic, ins.op_str, extra)
