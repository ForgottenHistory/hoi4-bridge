import sys, pefile
pe = pefile.PE(sys.argv[1], fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'], pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT']])
print("machine", hex(pe.FILE_HEADER.Machine), "imagebase", hex(pe.OPTIONAL_HEADER.ImageBase), "dllchar", hex(pe.OPTIONAL_HEADER.DllCharacteristics))
for s in pe.sections: print(s.Name.rstrip(b'\0').decode(), hex(s.VirtualAddress), hex(s.Misc_VirtualSize))
for e in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[]): print("IMP", e.dll.decode(), len(e.imports))
for e in getattr(pe,'DIRECTORY_ENTRY_DELAY_IMPORT',[]): print("DELAY", e.dll.decode(), len(e.imports))
