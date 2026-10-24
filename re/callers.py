import sys, re, struct, bisect, pefile
pe = pefile.PE(sys.argv[1], fast_load=True); pe.parse_data_directories(directories=[3])
text = next(s for s in pe.sections if s.Name.startswith(b'.text'))
code = pe.__data__[text.PointerToRawData:text.PointerToRawData+text.Misc_VirtualSize]; base=text.VirtualAddress
funcs = sorted((e.struct.BeginAddress, e.struct.EndAddress) for e in pe.DIRECTORY_ENTRY_EXCEPTION); starts=[f[0] for f in funcs]
def fo(r):
    i=bisect.bisect_right(starts,r)-1; return hex(funcs[i][0]) if i>=0 and funcs[i][0]<=r<funcs[i][1] else '?'
tg={int(t,16) for t in sys.argv[2:]}
for m in re.finditer(rb'[\xe8\xe9]', code):
    i=m.start(); t=base+i+5+struct.unpack_from('<i',code,i+1)[0]
    if t in tg: print(hex(t),'called from',hex(base+i),'func',fo(base+i), 'jmp' if code[i]==0xe9 else '')
# also pointers in data (vtables)
img=pe.get_memory_mapped_image()
for t in tg:
    va=struct.pack('<Q',0x140000000+t); p=img.find(va)
    while p!=-1: print(hex(t),'pointer at',hex(p)); p=img.find(va,p+1)
