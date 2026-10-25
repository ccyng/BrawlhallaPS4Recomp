import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lift64 import Eboot, FuncLifter, Unsupported
from ps4elf import Ps4Elf

def main():
    eb = Eboot(sys.argv[1], 0x10000000)
    names = {s['value']: s['name'] for s in Ps4Elf(sys.argv[1]).symbols if s['value']}
    funcs = dict(eb.funcs)
    for a in sys.argv[2:]:
        at = int(a, 16)
        start = max((f for f in funcs if f <= at), default=None)
        if start is None:
            print(f'{at:#x}: no function')
            continue
        fl = FuncLifter(eb, start, funcs[start], set())
        try:
            fl.lift()
            why = 'lifts'
        except Unsupported as ex:
            why = f'unsupported: {ex}'
        except Exception as ex:
            why = f'error: {type(ex).__name__} {ex}'
        print(f'{at:#x}: in {start:#x} (+{at - start:#x}, {funcs[start]} bytes) {names.get(start, "")}: {why}')

if __name__ == '__main__':
    main()
