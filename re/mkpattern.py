# Build a wildcarded AOB pattern for [start,end) and verify it matches exactly once in .text
import sys, re, pefile, capstone
pe = pefile.PE(sys.argv[1], fast_load=True); img = pe.get_memory_mapped_image()
start, end = int(sys.argv[2],16), int(sys.argv[3],16)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True
pat = []; notes = []
for ins in md.disasm(img[start:end], start):
    b = list(ins.bytes); mask = [True]*len(b)
    co = ins.disp_offset if ins.disp_offset else 0
    if 'rip' in ins.op_str and co: mask[co:co+4] = [False]*4
    if ins.mnemonic in ('call','jmp') and ins.imm_offset and ins.op_str.startswith('0x'):
        mask[ins.imm_offset:ins.imm_offset+4] = [False]*4
    if ins.mnemonic.startswith('j') and ins.size == 2: mask[1] = False
    notes.append(f'  +{ins.address-start:#04x} {ins.mnemonic} {ins.op_str}')
    pat += [f'{x:02X}' if m else '??' for x, m in zip(b, mask)]
text = next(s for s in pe.sections if s.Name.startswith(b'.text'))
code = img[text.VirtualAddress:text.VirtualAddress+text.Misc_VirtualSize]
rx = re.compile(b''.join(b'.' if p=='??' else re.escape(bytes([int(p,16)])) for p in pat), re.S)
hits = [hex(text.VirtualAddress+m.start()) for m in rx.finditer(code)]
print(' '.join(pat)); print('\n'.join(notes)); print('matches:', hits)
