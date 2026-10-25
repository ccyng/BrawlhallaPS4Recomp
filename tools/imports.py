import argparse
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mosaic'))
from ps4elf import Ps4Elf, R_X86_64_JUMP_SLOT, R_X86_64_GLOB_DAT, R_X86_64_64

TYPES = {R_X86_64_JUMP_SLOT: 'func', R_X86_64_GLOB_DAT: 'data', R_X86_64_64: 'abs64'}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('eboot')
    ap.add_argument('generated', nargs='?')
    ap.add_argument('--json')
    a = ap.parse_args()
    e = Ps4Elf(a.eboot)
    stubs = e.plt_stubs()
    slot_of_stub = stubs
    imports = e.imports()
    by_slot = {slot: (rtype, sym) for slot, rtype, sym, _ in imports}

    native = collections.Counter()
    jumps = 0
    if a.generated:
        for f in sorted(os.listdir(a.generated)):
            if f.startswith('og_lifted_') and f.endswith('.c'):
                text = open(os.path.join(a.generated, f)).read()
                native.update(int(m, 16) for m in re.findall(r'call_native\(c, \(og_base \+ 0x([0-9A-F]+)ull\)', text))
                jumps += text.count('og_host->jump_native(')

    calls = collections.Counter()
    for stub, slot in slot_of_stub.items():
        calls[slot] += native.get(stub, 0)
    rows = []
    for slot, rtype, sym, addend in imports:
        rows.append({'library': sym['library'], 'module': sym['module'], 'nid': sym['nid'],
                     'name': sym['name'] or '?', 'kind': TYPES.get(rtype, str(rtype)),
                     'slot': slot, 'calls': calls.get(slot, 0)})
    rows.sort(key=lambda r: (r['library'], r['name']))

    by_lib = collections.defaultdict(list)
    for r in rows:
        by_lib[r['library']].append(r)
    for lib, rs in sorted(by_lib.items(), key=lambda kv: -sum(r['calls'] for r in kv[1])):
        print(f'\n{lib} ({len(rs)} imports, {sum(r["calls"] for r in rs)} call sites)')
        for r in sorted(rs, key=lambda r: -r['calls']):
            print(f'  {r["calls"]:5}  {r["kind"]:5} {r["nid"]:12} {r["name"]}')

    other = {t: n for t, n in native.items() if t not in stubs}
    print(f'\n{len(rows)} imports; {sum(1 for r in rows if r["name"] == "?")} with no known name')
    if a.generated:
        print(f'call_native: {sum(native.values())} sites, {len(native)} targets; '
              f'{len(other)} targets are not PLT stubs ({sum(other.values())} sites)')
        for t, n in sorted(other.items(), key=lambda kv: -kv[1])[:40]:
            print(f'  {n:5}  {t:#x}')
        print(f'jump_native: {jumps} sites (indirect tail jumps; targets known only at run time)')
    if a.json:
        json.dump({'imports': rows, 'plt_stubs': {hex(k): hex(v) for k, v in stubs.items()},
                   'native_targets_not_plt': {hex(k): v for k, v in other.items()}},
                  open(a.json, 'w'), indent=1)

if __name__ == '__main__':
    main()
