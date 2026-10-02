#!/usr/bin/env python3
"""dis.py PE RVA [COUNT] - disassemble COUNT instructions at RVA, annotating IAT calls."""
import sys, pefile, capstone, re
pe = pefile.PE(sys.argv[1]); rva = int(sys.argv[2], 16); n = int(sys.argv[3]) if len(sys.argv) > 3 else 40
iat = {}
for e in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
    for i in e.imports:
        iat[i.address - pe.OPTIONAL_HEADER.ImageBase] = f'{e.dll.decode()}!{i.name.decode() if i.name else "#%d" % i.ordinal}'
cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
img = pe.get_memory_mapped_image()
for ins in list(cs.disasm(img[rva:rva + n * 15], rva))[:n]:
    ann = ''
    m = re.search(r'\[rip ([+-]) (0x[0-9a-f]+)\]', ins.op_str)
    if m:
        t = ins.address + ins.size + (int(m.group(2), 16) * (1 if m.group(1) == '+' else -1))
        ann = f'  ; {t:#x} {iat.get(t, "")}'
        if not iat.get(t):
            try:
                s = pe.get_string_at_rva(t, 80)
                if s and len(s) > 3 and all(32 <= c < 127 for c in s): ann += repr(s.decode())
                else:
                    w = img[t:t+120].decode('utf-16le', 'ignore').split('\0')[0]
                    if len(w) > 3 and w.isprintable(): ann += 'L' + repr(w)
            except Exception: pass
    print(f'{ins.address:#09x}: {ins.mnemonic:6} {ins.op_str}{ann}')
