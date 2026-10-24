import sys, re, pefile, collections
pe = pefile.PE(sys.argv[1], fast_load=True); data = pe.__data__
out = open(sys.argv[2], 'w', encoding='utf-8')
n = 0
for s in pe.sections:
    if s.Name.rstrip(b'\0') not in (b'.rdata', b'.data'): continue
    raw = data[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
    for m in re.finditer(rb'[\x20-\x7e\t]{4,}\x00', raw):
        out.write(f"{s.VirtualAddress+m.start():x}\t{m.group()[:-1].decode()}\n"); n += 1
print(n, 'strings')
