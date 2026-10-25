import argparse
import os
import re
import struct

DEFAULT_OPCODES = '/home/ven17b/Documents/VS/OrbisGlue/src/shader_recompiler/frontend/opcodes.h'

def load_opcodes(path):
    tables, cur = {}, None
    for line in open(path):
        m = re.match(r'enum class Opcode(\w+) : u32 \{', line)
        if m:
            cur = tables.setdefault(m.group(1), {})
            continue
        if cur is not None:
            if line.startswith('};'):
                cur = None
                continue
            m = re.match(r'\s*(\w+) = (\w+),', line)
            if m:
                cur.setdefault(int(m.group(2), 0), m.group(1).lower())
    return tables

def sreg(v, lit=None):
    if v <= 103:
        return f's{v}'
    names = {106: 'vcc_lo', 107: 'vcc_hi', 124: 'm0', 126: 'exec_lo', 127: 'exec_hi', 251: 'vccz',
             252: 'execz', 253: 'scc', 255: 'lit'}
    if v in names:
        return f'{lit:#x}' if v == 255 and lit is not None else names[v]
    if 128 <= v <= 192:
        return str(v - 128)
    if 193 <= v <= 208:
        return str(-(v - 192))
    f = {240: '0.5', 241: '-0.5', 242: '1.0', 243: '-1.0', 244: '2.0', 245: '-2.0', 246: '4.0', 247: '-4.0'}
    return f.get(v, f'?{v}')

def src9(v, lit=None):
    return f'v{v - 256}' if v >= 256 else sreg(v, lit)

def disasm(code, ops):
    words = list(struct.unpack(f'<{len(code) // 4}I', code[:len(code) // 4 * 4]))
    i, out = 0, []
    while i < len(words):
        w = words[i]
        at = i * 4
        n = 1
        lit = words[i + 1] if i + 1 < len(words) else None

        def need_lit(*fields):
            return any(f == 255 for f in fields)

        if w >> 23 == 0x17F:
            op = w >> 16 & 0x7F
            txt = f'{ops["SOPP"].get(op, op)} {w & 0xFFFF:#x}'
        elif w >> 23 == 0x17D:
            op, d, s0 = w >> 8 & 0xFF, w >> 16 & 0x7F, w & 0xFF
            n += need_lit(s0)
            txt = f'{ops["SOP1"].get(op, op)} {sreg(d)}, {sreg(s0, lit)}'
        elif w >> 23 == 0x17E:
            op, s0, s1 = w >> 16 & 0x7F, w & 0xFF, w >> 8 & 0xFF
            n += need_lit(s0, s1)
            txt = f'{ops["SOPC"].get(op, op)} {sreg(s0, lit)}, {sreg(s1, lit)}'
        elif w >> 28 == 0xB:
            op, d = w >> 23 & 0x1F, w >> 16 & 0x7F
            txt = f'{ops["SOPK"].get(op, op)} {sreg(d)}, {w & 0xFFFF:#x}'
        elif w >> 30 == 2:
            op, d, s0, s1 = w >> 23 & 0x7F, w >> 16 & 0x7F, w & 0xFF, w >> 8 & 0xFF
            n += need_lit(s0, s1)
            txt = f'{ops["SOP2"].get(op, op)} {sreg(d)}, {sreg(s0, lit)}, {sreg(s1, lit)}'
        elif w >> 27 == 0x18:
            op, d, base, imm, off = w >> 22 & 0x1F, w >> 15 & 0x7F, (w >> 9 & 0x3F) * 2, w >> 8 & 1, w & 0xFF
            o = f'{off * 4:#x}' if imm else sreg(off, lit)
            if not imm and off == 255:
                n += 1
            txt = f'{ops["SMRD"].get(op, op)} s{d}, s[{base}:{base + 1}], {o}'
        elif w >> 25 == 0x3F:
            op, d, s0 = w >> 9 & 0xFF, w >> 17 & 0xFF, w & 0x1FF
            n += need_lit(s0)
            txt = f'{ops["VOP1"].get(op, op)} v{d}, {src9(s0, lit)}'
        elif w >> 25 == 0x3E:
            op, s0, s1 = w >> 17 & 0xFF, w & 0x1FF, w >> 9 & 0xFF
            n += need_lit(s0)
            txt = f'{ops["VOPC"].get(op, op)} vcc, {src9(s0, lit)}, v{s1}'
        elif w >> 31 == 0:
            op, d, s0, s1 = w >> 25 & 0x3F, w >> 17 & 0xFF, w & 0x1FF, w >> 9 & 0xFF
            n += need_lit(s0)
            extra = ''
            name = ops['VOP2'].get(op, str(op))
            if name in ('v_madmk_f32', 'v_madak_f32'):
                n = 2
                extra = f', {lit:#x}'
            txt = f'{name} v{d}, {src9(s0, lit)}, v{s1}{extra}'
        elif w >> 26 == 0x34:
            w1 = words[i + 1]
            n = 2
            op, d = w >> 17 & 0x1FF, w & 0xFF
            s0, s1, s2 = w1 & 0x1FF, w1 >> 9 & 0x1FF, w1 >> 18 & 0x1FF
            neg, omod = w1 >> 29, w1 >> 27 & 3
            absm, clamp = w >> 8 & 7, w >> 11 & 1
            if op < 256:
                name = ops['VOPC'].get(op, f'vopc{op}')
                dst = sreg(d)
            elif op < 384:
                name = ops['VOP2'].get(op - 256, f'vop2_{op - 256}')
                dst = f'v{d}'
            elif op >= 384 + 0 and op < 448 + 256 and (op - 384) in ops['VOP1'] and op >= 0x180:
                name = ops['VOP1'].get(op - 384, f'vop1_{op - 384}')
                dst = f'v{d}'
            else:
                name = ops['VOP3'].get(op, f'vop3_{op}')
                dst = f'v{d}'
            if op >= 0x140 and op < 0x180:
                name = ops['VOP3'].get(op, name)
            mods = []

            def m(k, s):
                s = src9(s)
                if absm >> k & 1:
                    s = f'|{s}|'
                if neg >> k & 1:
                    s = '-' + s
                return s
            srcs = [m(0, s0), m(1, s1), m(2, s2)]
            if clamp:
                mods.append('clamp')
            if omod:
                mods.append(['', 'mul:2', 'mul:4', 'div:2'][omod])
            sdst = f' s{w >> 8 & 0x7F}' if name.endswith(('_co', 'addc_u32', 'subb_u32', 'sub_i32', 'add_i32', 'subrev_i32',
                                                         'div_scale_f32', 'div_scale_f64')) else ''
            txt = f'{name}_e64 {dst},{sdst} {", ".join(srcs)} {" ".join(mods)}'
        elif w >> 26 == 0x32:
            op, d, attr, chan, s = w >> 16 & 3, w >> 18 & 0xFF, w >> 10 & 0x3F, w >> 8 & 3, w & 0xFF
            txt = f'{ops["VINTRP"].get(op, op)} v{d}, v{s}, attr{attr}.{"xyzw"[chan]}'
        elif w >> 26 == 0x38 or w >> 26 == 0x3A:
            w1 = words[i + 1]
            n = 2
            mt = w >> 26 == 0x3A
            op = (w >> 16 & 7) if mt else (w >> 18 & 0x7F)
            off, offen, idxen = w & 0xFFF, w >> 12 & 1, w >> 13 & 1
            vaddr, vdata, srsrc, soff = w1 & 0xFF, w1 >> 8 & 0xFF, (w1 >> 16 & 0x1F) * 4, w1 >> 24
            fmt = f' dfmt:{w >> 19 & 0xF} nfmt:{w >> 23 & 7}' if mt else ''
            name = ops['MTBUF' if mt else 'MUBUF'].get(op, op)
            txt = (f'{name} v{vdata}, v{vaddr}, s[{srsrc}:{srsrc + 3}], {sreg(soff)} off:{off:#x}'
                   f'{" offen" if offen else ""}{" idxen" if idxen else ""}{fmt}')
        elif w >> 26 == 0x3C:
            w1 = words[i + 1]
            n = 2
            op, dmask = w >> 18 & 0x7F, w >> 8 & 0xF
            vaddr, vdata, srsrc, ssamp = w1 & 0xFF, w1 >> 8 & 0xFF, (w1 >> 16 & 0x1F) * 4, (w1 >> 21 & 0x1F) * 4
            txt = (f'{ops["MIMG"].get(op, op)} v{vdata}, v{vaddr}, s[{srsrc}:{srsrc + 7}], s[{ssamp}:{ssamp + 3}] '
                   f'dmask:{dmask:#x}')
        elif w >> 26 == 0x3E:
            w1 = words[i + 1]
            n = 2
            en, tgt, compr, done, vm = w & 0xF, w >> 4 & 0x3F, w >> 10 & 1, w >> 11 & 1, w >> 12 & 1
            t = f'mrt{tgt}' if tgt < 8 else 'mrtz' if tgt == 8 else 'null' if tgt == 9 else (
                f'pos{tgt - 12}' if 12 <= tgt < 16 else f'param{tgt - 32}')
            vs = ' '.join(f'v{w1 >> 8 * k & 0xFF}' if en >> k & 1 else 'off' for k in range(4))
            txt = f'exp {t} {vs}{" compr" if compr else ""}{" done" if done else ""}{" vm" if vm else ""}'
        elif w >> 26 == 0x36:
            n = 2
            txt = f'ds op{w >> 18 & 0xFF}'
        else:
            txt = f'.word {w:#010x}'
        out.append(f'{at:04x}: {txt}')
        i += n
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('bin')
    ap.add_argument('--opcodes', default=DEFAULT_OPCODES)
    a = ap.parse_args()
    ops = load_opcodes(a.opcodes)
    print('\n'.join(disasm(open(a.bin, 'rb').read(), ops)))

if __name__ == '__main__':
    main()
