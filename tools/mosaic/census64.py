import argparse
import collections

import capstone
from capstone import x86

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lift64 import Eboot, FuncLifter, Unsupported

def form(ins):
    kinds = []
    for op in ins.operands:
        if op.type == x86.X86_OP_REG:
            n = ins.reg_name(op.reg)
            kinds.append('ymm' if n.startswith('ymm') else 'xmm' if n.startswith('xmm') else f'r{op.size * 8}')
        elif op.type == x86.X86_OP_MEM:
            kinds.append(f'm{op.size * 8}')
        elif op.type == x86.X86_OP_IMM:
            kinds.append('i')
    return ins.mnemonic + ' ' + ','.join(kinds)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('eboot')
    ap.add_argument('--base', type=lambda s: int(s, 0), default=0x10000000)
    ap.add_argument('--top', type=int, default=120)
    args = ap.parse_args()

    eb = Eboot(args.eboot, args.base)
    occ = collections.Counter()
    funcs_with = collections.Counter()
    only = collections.Counter()
    data_in_func = 0
    undecodable = collections.Counter()
    lifted = 0
    for start, size in eb.funcs:
        fl = FuncLifter(eb, start, size, set())
        try:
            fl.decode()
        except Unsupported as ex:
            data_in_func += 1
            undecodable[str(ex)] += 1
            continue
        insns = fl.insns
        bad = set()
        for ins in insns:
            fl.out = []
            try:
                fl.lift_insn(ins, ins.address + ins.size)
            except Unsupported:
                f = form(ins)
                occ[f] += 1
                bad.add(f)
            except Exception:
                f = 'error ' + form(ins)
                occ[f] += 1
                bad.add(f)
        if not bad:
            lifted += 1
            continue
        for f in bad:
            funcs_with[f] += 1
        if len(bad) == 1:
            only[next(iter(bad))] += 1
    total = len(eb.funcs)
    print(f'functions {total}, would lift now {lifted} ({100.0 * lifted / total:.1f}%), '
          f'not decodable {data_in_func} {dict(undecodable)}')
    print(f'{"form":40s} {"occurs":>8s} {"in funcs":>9s} {"only one":>9s}')
    for f, n in funcs_with.most_common(args.top):
        print(f'{f:40s} {occ[f]:8d} {n:9d} {only[f]:9d}')

if __name__ == '__main__':
    main()
