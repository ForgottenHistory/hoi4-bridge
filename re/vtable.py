# find vftables for an RTTI class name, e.g. vtable.py exe .?AVCCountry@@
import sys, struct, pefile
pe = pefile.PE(sys.argv[1], fast_load=True); img = pe.get_memory_mapped_image(); IB = pe.OPTIONAL_HEADER.ImageBase
name = sys.argv[2].encode() + b'\0'
p = img.find(name)
while p != -1:
    td = p - 0x10                      # TypeDescriptor: vfptr, spare, name
    q = img.find(struct.pack('<I', td))
    while q != -1:
        col = q - 12
        if struct.unpack_from('<I', img, col)[0] == 1 and struct.unpack_from('<I', img, col+20)[0] == col:
            off = struct.unpack_from('<I', img, col+4)[0]
            r = img.find(struct.pack('<Q', IB + col))
            while r != -1:
                vt = r + 8
                fns = [struct.unpack_from('<Q', img, vt + 8*i)[0] - IB for i in range(int(sys.argv[3]) if len(sys.argv) > 3 else 12)]
                print(f'vftable {IB+vt:#x} (subobject offset {off:#x}):', ' '.join(f'{f:#x}' for f in fns))
                r = img.find(struct.pack('<Q', IB + col), r + 1)
        q = img.find(struct.pack('<I', td), q + 1)
    p = img.find(name, p + 1)
