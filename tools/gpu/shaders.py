import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gcn

TYPES = {0: 'ps', 1: 'vs', 2: 'gs', 3: 'es', 4: 'hs', 5: 'ls', 6: 'cs'}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('eboot')
    ap.add_argument('out')
    a = ap.parse_args()
    d = open(a.eboot, 'rb').read()
    os.makedirs(a.out, exist_ok=True)
    ops = gcn.load_opcodes(gcn.DEFAULT_OPCODES)
    pos = 0
    while (pos := d.find(b'OrbShdr', pos)) >= 0:
        bits, = struct.unpack_from('<I', d, pos + 8)
        length = bits >> 8 & 0xFFFFFF
        stype = TYPES.get(bits >> 2 & 0xF, '?')
        h0, h1 = struct.unpack_from('<II', d, pos + 0x10)
        start = d.rfind(b'\xff\x03\xeb\xbe', max(0, pos - length - 0x200), pos)
        if start < 0 or start + length > pos or length == 0:
            pos += 7
            continue
        code = d[start:start + length]
        name = f'{h1:08x}{h0:08x}'
        open(os.path.join(a.out, name + '.bin'), 'wb').write(code)
        open(os.path.join(a.out, name + '.s'), 'w').write('\n'.join(gcn.disasm(code, ops)) + '\n')
        print(f'{start:#010x} {stype} {length:6} {name}')
        pos += 7

if __name__ == '__main__':
    main()
