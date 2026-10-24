# count direct call sites for every function starting in [lo,hi)
import sys, re, struct, bisect, pefile, collections
pe = pefile.PE(sys.argv[1], fast_load=True); pe.parse_data_directories(directories=[3])
text = next(s for s in pe.sections if s.Name.startswith(b'.text')); base = text.VirtualAddress
code = pe.__data__[text.PointerToRawData:text.PointerToRawData+text.Misc_VirtualSize]
lo, hi = int(sys.argv[2],16), int(sys.argv[3],16)
starts = {e.struct.BeginAddress for e in pe.DIRECTORY_ENTRY_EXCEPTION if lo <= e.struct.BeginAddress < hi}
cnt = collections.Counter()
for m in re.finditer(rb'[\xe8\xe9]', code):
    i = m.start(); t = base+i+5+struct.unpack_from('<i', code, i+1)[0]
    if t in starts: cnt[t] += 1
for t, n in cnt.most_common(int(sys.argv[4]) if len(sys.argv) > 4 else 15): print(f'{t:#x} {n}')
