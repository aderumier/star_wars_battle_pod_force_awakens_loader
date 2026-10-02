#!/usr/bin/env python3
"""func.py PE RVA... - print the .pdata function range containing each RVA"""
import sys, pefile
pe = pefile.PE(sys.argv[1], fast_load=True)
e = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
d = pe.get_data(e.VirtualAddress, e.Size)
fns = [(int.from_bytes(d[i:i+4], 'little'), int.from_bytes(d[i+4:i+8], 'little')) for i in range(0, len(d), 12)]
for a in sys.argv[2:]:
    a = int(a, 16)
    for b, en in fns:
        if b <= a < en: print(f'{a:#x} in {b:#x}-{en:#x}')
