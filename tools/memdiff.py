#!/usr/bin/env python3
"""memdiff.py PID MODULE_FILE [OUTDIR]
Dump the image of MODULE_FILE mapped in Wine process PID (needs root for
/proc/PID/mem) and list every byte range that differs from the file
(relocations applied, IAT ignored). Shows original/patched disassembly."""
import sys, os, pefile, capstone
pid, path = int(sys.argv[1]), sys.argv[2]
out = sys.argv[3] if len(sys.argv) > 3 else None
pe = pefile.PE(path)
name = os.path.basename(path).lower()
base = None
for l in open(f'/proc/{pid}/maps'):
    p = l.split()
    if len(p) >= 6 and os.path.basename(' '.join(p[5:])).lower() == name and int(p[2], 16) == 0:
        base = int(p[0].split('-')[0], 16); break
if base is None: sys.exit('module not mapped')
size = pe.OPTIONAL_HEADER.SizeOfImage
mem = bytearray()
with open(f'/proc/{pid}/mem', 'rb', 0) as f:
    for a in range(base, base + size, 0x1000):
        try: f.seek(a); mem += f.read(0x1000)
        except OSError: mem += b'\0' * 0x1000
if out:
    open(os.path.join(out, name + f'.{base:x}.mem'), 'wb').write(mem)
pe.relocate_image(base)
img = bytearray(pe.get_memory_mapped_image())
img += b'\0' * (size - len(img))
skip = []
for d in (1, 12):  # import dir, IAT
    e = pe.OPTIONAL_HEADER.DATA_DIRECTORY[d]
    if e.Size: skip.append((e.VirtualAddress, e.VirtualAddress + e.Size))
cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
print(f'{name} base {base:#x} size {size:#x}')
for s in pe.sections:
    if not (s.Characteristics & 0x20000000) and s.Name.rstrip(b'\0') not in (b'.rdata',):
        pass
    lo, hi = s.VirtualAddress, s.VirtualAddress + s.Misc_VirtualSize
    if s.Characteristics & 0x80000000: continue  # writable section: data, too noisy
    i = lo
    while i < hi:
        if img[i] == mem[i] or any(a <= i < b for a, b in skip): i += 1; continue
        j = i
        while j < hi and (img[j] != mem[j] or (j + 8 < hi and img[j:j+8] != mem[j:j+8])): j += 1
        print(f'\n[{s.Name.rstrip(b"\0").decode()}] rva {i:#x}-{j:#x} ({j-i} bytes)')
        print('  file:', img[i:j][:48].hex(), '\n  mem :', mem[i:j][:48].hex())
        if s.Characteristics & 0x20000000:
            for tag, buf in (('orig', img), ('new ', mem)):
                for ins in list(cs.disasm(bytes(buf[i:i+24]), i))[:4]:
                    print(f'  {tag} {ins.address:#x}: {ins.mnemonic} {ins.op_str}')
        i = j
