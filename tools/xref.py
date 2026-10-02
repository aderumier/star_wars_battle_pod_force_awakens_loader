#!/usr/bin/env python3
"""xref.py PE TARGET_RVA [TARGET_RVA...]  -> list instructions referencing the RVAs
(rip-relative mem operands, direct call/jmp). Use pedis.py to see context."""
import sys, pefile, capstone, re
pe = pefile.PE(sys.argv[1], fast_load=True)
targets = {int(x, 16) for x in sys.argv[2:]}
ib = pe.OPTIONAL_HEADER.ImageBase
cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); cs.skipdata = True
for s in pe.sections:
    if not s.Characteristics & 0x20000000: continue
    data = s.get_data(); va = s.VirtualAddress
    # fast pre-scan: rip-relative disp32 candidates
    for off in range(0, len(data) - 4):
        d = int.from_bytes(data[off:off+4], 'little', signed=True)
        for t in targets:
            # instruction end could be off+4 .. off+5 (imm8) .. off+8 (imm32)
            for extra in (0, 1, 2, 4):
                if va + off + 4 + extra + d == t:
                    st = max(0, off - 4)
                    for b in range(off - 1, st - 1, -1):
                        for ins in cs.disasm(data[b:b+16], va + b, 1):
                            if ins.size == off - b + 4 + extra:
                                print(f'{ins.address:#x}: {ins.mnemonic} {ins.op_str}  -> {t:#x}')
