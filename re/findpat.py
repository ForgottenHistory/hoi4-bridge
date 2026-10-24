import sys, re, pefile
pe = pefile.PE(sys.argv[1], fast_load=True); img = pe.get_memory_mapped_image()
text = next(s for s in pe.sections if s.Name.startswith(b'.text'))
code = img[text.VirtualAddress:text.VirtualAddress+text.Misc_VirtualSize]
for pat in sys.argv[2:]:
    rx = re.compile(b''.join(b'.' if p=='??' else re.escape(bytes([int(p,16)])) for p in pat.split()), re.S)
    print(pat[:40], '->', [hex(text.VirtualAddress+m.start()) for m in rx.finditer(code)])
