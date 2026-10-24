import sys, re, pefile
pe = pefile.PE(sys.argv[1], fast_load=True)
data = pe.__data__
pats = [p.encode() for p in sys.argv[2:]]
for s in pe.sections:
    name = s.Name.rstrip(b'\0').decode()
    if name not in ('.rdata','.data'): continue
    raw = data[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
    for m in re.finditer(rb'[\x20-\x7e]{3,200}\x00', raw):
        st = m.group()[:-1]
        if any(p.lower() in st.lower() for p in pats):
            print(name, hex(s.VirtualAddress+m.start()), st.decode()[:150])
